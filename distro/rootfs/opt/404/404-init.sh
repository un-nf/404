#!/bin/sh
set -eu

WIN_USER=$(cat /opt/404/win-user)
CONFIG_PATH="/mnt/c/Users/${WIN_USER}/AppData/Roaming/404/static/static.runtime.toml"
PIN_ROOT="/sys/fs/bpf/404"
PACKET_PROFILE_PIN="${PIN_ROOT}/fingerprint_profiles"

if [ ! -f "$CONFIG_PATH" ]; then
  echo "missing runtime config: $CONFIG_PATH" >&2
  exit 1
fi

ensure_bpffs() {
  mkdir -p /sys/fs/bpf
  if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  fi
  mkdir -p "$PIN_ROOT"
}

pin_bpf_map() {
  map_name="$1"
  pin_path="$2"

  if ! command -v bpftool >/dev/null 2>&1; then
    return 0
  fi

  truncated_name=$(printf '%s' "$map_name" | cut -c1-15)
  map_id=$(bpftool map show 2>/dev/null | awk -F': ' -v map_name="$map_name" -v truncated_name="$truncated_name" '
    {
      id = $1
      name = $2
      sub(/^.* name /, "", name)
      sub(/ .*/, "", name)
      if (name == map_name || name == truncated_name) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
        print id
      }
    }
  ' | awk 'NF { print $1 }' | sort -n | tail -n 1)
  if [ -z "$map_id" ]; then
    return 0
  fi

  rm -f "$pin_path"
  bpftool map pin id "$map_id" "$pin_path" 2>/dev/null || true
}

attach_ifaces() {
  if [ -n "${EGRESS_IFACES:-}" ]; then
    printf '%s\n' "$EGRESS_IFACES" | tr ', ' '\n' | awk 'NF { print }'
    return
  fi

  ip -o link show up | awk -F': ' '/: eth[0-9]+:/ { print $2 }'
}

# Attach the eBPF classifier best-effort; repeated boots should remain harmless.
ensure_bpffs
for iface in $(attach_ifaces); do
  tc qdisc add dev "$iface" clsact 2>/dev/null || true
  tc filter add dev "$iface" egress bpf da obj /opt/404/ttl_editor.o sec classifier 2>/dev/null || true
done
pin_bpf_map fingerprint_profiles "$PACKET_PROFILE_PIN"

exec /opt/404/static \
  --config "$CONFIG_PATH" \
  --mode proxy