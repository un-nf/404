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

  map_id=$(bpftool map show name "$map_name" 2>/dev/null | awk -F: 'NR==1 {gsub(/^[[:space:]]+/, "", $1); print $1}')
  if [ -z "$map_id" ]; then
    return 0
  fi

  rm -f "$pin_path"
  bpftool map pin id "$map_id" "$pin_path" 2>/dev/null || true
}

# Attach the eBPF classifier best-effort; repeated boots should remain harmless.
ensure_bpffs
tc qdisc add dev eth0 clsact 2>/dev/null || true
tc filter add dev eth0 egress bpf da obj /opt/404/ttl_editor.o sec classifier 2>/dev/null || true
pin_bpf_map fingerprint_profiles "$PACKET_PROFILE_PIN"

exec /opt/404/static \
  --config "$CONFIG_PATH" \
  --mode proxy