#!/usr/bin/env bash
set -euo pipefail

PIN_ROOT=${STATIC_EBPF_PIN_ROOT:-/sys/fs/bpf/404}
PACKET_PROFILE_PIN=${STATIC_EBPF_MAP_PATH:-${PIN_ROOT}/fingerprint_profiles}
PIN_OWNER_UID=${PIN_OWNER_UID:-$(id -u)}
PIN_OWNER_GID=${PIN_OWNER_GID:-$(id -g)}

map_id_by_name() {
    local requested_name=$1
    local truncated_name=${requested_name:0:15}

    sudo bpftool map show 2>/dev/null | awk -F': ' -v requested_name="$requested_name" -v truncated_name="$truncated_name" '
        {
            id = $1
            name = $2
            sub(/^.* name /, "", name)
            sub(/ .*/, "", name)
            if (name == requested_name || name == truncated_name) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
                print id
            }
        }
    ' | sort -n | tail -n 1
}

ensure_bpffs() {
    sudo mkdir -p /sys/fs/bpf
    if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
        sudo mount -t bpf bpf /sys/fs/bpf
    fi
    sudo mkdir -p "$PIN_ROOT"
    sudo chown "$PIN_OWNER_UID:$PIN_OWNER_GID" "$PIN_ROOT"
    sudo chmod 755 "$PIN_ROOT"
}

pin_bpf_map() {
    local map_name=$1
    local pin_path=$2

    if ! command -v bpftool >/dev/null 2>&1; then
        echo "warning: bpftool not found; skipping map pin for ${map_name}" >&2
        return
    fi

    sudo rm -f "$pin_path"

    local map_id
    map_id=$(map_id_by_name "$map_name")
    if [[ -z "$map_id" ]]; then
        echo "warning: map ${map_name} not found after attach; skipping pin" >&2
        return
    fi

    sudo bpftool map pin id "$map_id" "$pin_path"
    sudo chown "$PIN_OWNER_UID:$PIN_OWNER_GID" "$pin_path"
    sudo chmod 600 "$pin_path"
}

resolve_attach_ifaces() {
    if [[ -n "${EGRESS_IFACES:-}" ]]; then
        printf '%s\n' "${EGRESS_IFACES}" | tr ', ' '\n' | awk 'NF { print }'
        return
    fi

    ip -o link show up | awk -F': ' '/: eth[0-9]+:/ { print $2 }'
}

mapfile -t ATTACH_IFACES < <(resolve_attach_ifaces)

if [[ ${#ATTACH_IFACES[@]} -eq 0 ]]; then
    echo "Unable to determine attach interfaces" >&2
    exit 1
fi

printf 'Using attach interfaces: %s\n' "${ATTACH_IFACES[*]}"

for iface in "${ATTACH_IFACES[@]}"; do
    tc qdisc del dev "${iface}" clsact >/dev/null 2>&1 || true
    tc qdisc add dev "${iface}" clsact
    tc filter add dev "${iface}" egress bpf da obj /opt/404/ttl_editor.o sec classifier
    tc -s filter show dev "${iface}" egress
done

pin_bpf_map fingerprint_profiles "$PACKET_PROFILE_PIN"
echo "Pinned fingerprint_profiles at ${PACKET_PROFILE_PIN}"