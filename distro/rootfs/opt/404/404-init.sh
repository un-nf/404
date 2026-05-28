#!/bin/sh
set -eu

WIN_USER=$(cat /opt/404/win-user)
CONFIG_PATH=""
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

resolve_tool() {
  tool_name="$1"
  shift

  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return 0
  fi

  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

BPFTOOL_BIN=$(resolve_tool bpftool /usr/sbin/bpftool /sbin/bpftool || true)
TC_BIN=$(resolve_tool tc /usr/sbin/tc /sbin/tc || true)

for candidate in \
  "/mnt/c/Users/${WIN_USER}/AppData/Roaming/com.404.app/static/static.runtime.toml" \
  "/mnt/c/Users/${WIN_USER}/AppData/Roaming/404/static/static.runtime.toml"
do
  if [ -f "$candidate" ]; then
    CONFIG_PATH="$candidate"
    break
  fi
done
PIN_ROOT="/sys/fs/bpf/404"
PACKET_PROFILE_PIN="${PIN_ROOT}/fingerprint_profiles"
PROGRAM_PIN_ROOT="${PIN_ROOT}/ttl_programs"
CLASSIFIER_PROGRAM_PIN="${PROGRAM_PIN_ROOT}/tc_counter"

if [ -z "$CONFIG_PATH" ]; then
  echo "missing runtime config under /mnt/c/Users/${WIN_USER}/AppData/Roaming/{com.404.app,404}/static" >&2
  exit 1
fi

ensure_bpffs() {
  mkdir -p /sys/fs/bpf
  if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  fi
  mkdir -p "$PIN_ROOT"
}

load_classifier_program() {
  if [ -z "$BPFTOOL_BIN" ]; then
    return 1
  fi

  rm -rf "$PROGRAM_PIN_ROOT"
  mkdir -p "$PROGRAM_PIN_ROOT"

  if ! $BPFTOOL_BIN prog loadall /opt/404/ttl_editor.o "$PROGRAM_PIN_ROOT" >/dev/null 2>&1; then
    rm -rf "$PROGRAM_PIN_ROOT"
    return 1
  fi

  [ -f "$CLASSIFIER_PROGRAM_PIN" ]
}

pin_bpf_map() {
  map_name="$1"
  pin_path="$2"

  if [ -z "$BPFTOOL_BIN" ]; then
    return 0
  fi

  truncated_name=$(printf '%s' "$map_name" | cut -c1-15)
  map_id=$($BPFTOOL_BIN map show 2>/dev/null | awk -F': ' -v map_name="$map_name" -v truncated_name="$truncated_name" '
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
  $BPFTOOL_BIN map pin id "$map_id" "$pin_path" 2>/dev/null || true
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
if [ -n "$TC_BIN" ]; then
  classifier_program_loaded=0
  if load_classifier_program; then
    classifier_program_loaded=1
  fi

  for iface in $(attach_ifaces); do
    $TC_BIN qdisc add dev "$iface" clsact 2>/dev/null || true

    if [ "$classifier_program_loaded" -eq 1 ]; then
      $TC_BIN filter add dev "$iface" egress bpf da pinned "$CLASSIFIER_PROGRAM_PIN" 2>/dev/null || true
    else
      $TC_BIN filter add dev "$iface" egress bpf da obj /opt/404/ttl_editor.o sec classifier 2>/dev/null || true
    fi
  done
  pin_bpf_map fingerprint_profiles "$PACKET_PROFILE_PIN"
fi

exec /opt/404/static \
  --config "$CONFIG_PATH" \
  --mode proxy