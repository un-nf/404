#!/usr/bin/env bash
set -euo pipefail

MAP_PATH=${STATIC_EBPF_MAP_PATH:-/sys/fs/bpf/404/fingerprint_profiles}
PROFILE_KEY_HEX=${PROFILE_KEY_HEX:-"00 00 00 00"}

SUDO=()
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO=(sudo)
fi

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

require_cmd bpftool
require_cmd awk

map_id_by_name() {
    local requested_name=$1
    local truncated_name=${requested_name:0:15}

    "${SUDO[@]}" bpftool map show 2>/dev/null | awk -F': ' -v requested_name="$requested_name" -v truncated_name="$truncated_name" '
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

resolve_attach_ifaces() {
    if [[ -n "${EGRESS_IFACES:-}" ]]; then
        printf '%s\n' "${EGRESS_IFACES}" | tr ', ' '\n' | awk 'NF { print }'
        return
    fi

    ip -o link show up | awk -F': ' '/: eth[0-9]+:/ { print $2 }'
}

hex_byte() {
    local token=${1#0x}
    printf '%d' "$((16#$token))"
}

le_u16() {
    local lo hi
    lo=$(hex_byte "$1")
    hi=$(hex_byte "$2")
    printf '%d' "$((lo | (hi << 8)))"
}

join_by() {
    local separator=$1
    shift
    local first=1
    for value in "$@"; do
        if [[ $first -eq 1 ]]; then
            printf '%s' "$value"
            first=0
        else
            printf '%s%s' "$separator" "$value"
        fi
    done
}

decode_tcp_options() {
    local -n option_bytes_ref=$1
    local options_len=$2
    local index=0
    local decoded=()

    while [[ $index -lt $options_len ]]; do
        local kind
        kind=$(hex_byte "${option_bytes_ref[$index]}")

        case $kind in
            0)
                decoded+=("EOL")
                break
                ;;
            1)
                decoded+=("NOP")
                index=$((index + 1))
                ;;
            2)
                if [[ $((index + 3)) -ge $options_len ]]; then
                    decoded+=("MSS(truncated)")
                    break
                fi
                decoded+=("MSS=$(le_u16 "${option_bytes_ref[$((index + 2))]}" "${option_bytes_ref[$((index + 3))]}")")
                index=$((index + 4))
                ;;
            3)
                if [[ $((index + 2)) -ge $options_len ]]; then
                    decoded+=("WS(truncated)")
                    break
                fi
                decoded+=("WS=$(hex_byte "${option_bytes_ref[$((index + 2))]}")")
                index=$((index + 3))
                ;;
            4)
                decoded+=("SACK_PERMITTED")
                index=$((index + 2))
                ;;
            8)
                decoded+=("TIMESTAMP")
                index=$((index + 10))
                ;;
            *)
                local length_index=$((index + 1))
                if [[ $length_index -ge $options_len ]]; then
                    decoded+=("OPT${kind}(truncated)")
                    break
                fi
                local option_len
                option_len=$(hex_byte "${option_bytes_ref[$length_index]}")
                if [[ $option_len -le 0 ]]; then
                    decoded+=("OPT${kind}(invalid-len)")
                    break
                fi
                decoded+=("OPT${kind}")
                index=$((index + option_len))
                ;;
        esac
    done

    join_by ',' "${decoded[@]}"
}

echo "== Routing =="
ip route get 1.1.1.1 || true
echo

echo "== Live attach candidates =="
mapfile -t ATTACH_IFACES < <(resolve_attach_ifaces)
if [[ ${#ATTACH_IFACES[@]} -eq 0 ]]; then
    echo "No live eth* interfaces found"
else
    printf '%s\n' "${ATTACH_IFACES[@]}"
fi
echo

echo "== TC filters =="
for iface in "${ATTACH_IFACES[@]}"; do
    echo "-- ${iface} --"
    "${SUDO[@]}" tc -s filter show dev "$iface" egress || true
done
echo

echo "== Pinned packet profile map =="
if ! "${SUDO[@]}" bpftool map show pinned "$MAP_PATH" >/dev/null 2>&1; then
    echo "Pinned packet profile map not found at ${MAP_PATH}"
    echo "If you used scripts/verify-ebpf-attach.sh previously, rerun it after syncing the latest repo changes so it mounts bpffs and pins fingerprint_profiles."
    echo
    echo "== Protocol counter map =="
    protocol_counter_id=$(map_id_by_name protocol_counter)
    if [[ -n "${protocol_counter_id}" ]]; then
        "${SUDO[@]}" bpftool map dump id "$protocol_counter_id"
    else
        echo "protocol_counter map not found"
    fi
    exit 0
fi

"${SUDO[@]}" bpftool map show pinned "$MAP_PATH"
if command -v stat >/dev/null 2>&1; then
    map_owner=$("${SUDO[@]}" stat -c '%U:%G %a %n' "$MAP_PATH" 2>/dev/null || true)
    if [[ -n "$map_owner" ]]; then
        echo "Pinned map owner: ${map_owner}"
    fi
fi
lookup_output=$("${SUDO[@]}" bpftool map lookup pinned "$MAP_PATH" key hex $PROFILE_KEY_HEX)
printf '%s\n' "$lookup_output"

json_number_field() {
    local field_name=$1
    printf '%s\n' "$lookup_output" | sed -n "s/.*\"${field_name}\":[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -n1
}

declare -a OPTION_BYTES=()

if printf '%s\n' "$lookup_output" | grep -q '"value"'; then
    ttl=$(json_number_field ttl)
    tos=$(json_number_field tos)
    tcp_window=$(json_number_field tcp_window)
    tcp_mss=$(json_number_field tcp_mss)
    tcp_window_scale=$(json_number_field tcp_window_scale)
    randomize_tcp_timestamp=$(json_number_field randomize_tcp_timestamp)
    randomize_ipv4_id=$(json_number_field randomize_ipv4_id)
    randomize_ipv6_flow=$(json_number_field randomize_ipv6_flow)
    options_len=$(json_number_field options_len)
    mss_value_offset=$(json_number_field mss_value_offset)
    tsval_value_offset=$(json_number_field tsval_value_offset)
    window_scale_value_offset=$(json_number_field window_scale_value_offset)

    options_csv=$(printf '%s\n' "$lookup_output" | tr -d '\n' | sed -n 's/.*"options":[[:space:]]*\[\([^]]*\)\].*/\1/p')
    if [[ -z "$options_csv" ]]; then
        echo "Unable to decode pinned packet profile options from bpftool output" >&2
        exit 1
    fi

    options_csv=${options_csv// /}
    IFS=',' read -r -a option_numbers <<< "$options_csv"
    for value in "${option_numbers[@]}"; do
        printf -v option_hex '%02x' "$value"
        OPTION_BYTES+=("$option_hex")
    done
else
    mapfile -t VALUE_TOKENS < <(
        printf '%s\n' "$lookup_output" |
            awk '
                /^value:/ {
                    sub(/^value:[[:space:]]*/, "");
                    for (i = 1; i <= NF; ++i) print $i;
                    capture = 1;
                    next;
                }
                capture {
                    for (i = 1; i <= NF; ++i) print $i;
                }
            '
    )

    if [[ ${#VALUE_TOKENS[@]} -lt 56 ]]; then
        echo "Unable to decode pinned packet profile from bpftool output" >&2
        exit 1
    fi

    ttl=$(hex_byte "${VALUE_TOKENS[0]}")
    tos=$(hex_byte "${VALUE_TOKENS[1]}")
    tcp_window=$(le_u16 "${VALUE_TOKENS[2]}" "${VALUE_TOKENS[3]}")
    tcp_mss=$(le_u16 "${VALUE_TOKENS[4]}" "${VALUE_TOKENS[5]}")
    tcp_window_scale=$(hex_byte "${VALUE_TOKENS[6]}")
    randomize_tcp_timestamp=$(hex_byte "${VALUE_TOKENS[7]}")
    randomize_ipv4_id=$(hex_byte "${VALUE_TOKENS[8]}")
    randomize_ipv6_flow=$(hex_byte "${VALUE_TOKENS[9]}")
    options_len=$(hex_byte "${VALUE_TOKENS[10]}")
    mss_value_offset=$(hex_byte "${VALUE_TOKENS[11]}")
    tsval_value_offset=$(hex_byte "${VALUE_TOKENS[12]}")
    window_scale_value_offset=$(hex_byte "${VALUE_TOKENS[13]}")

    for ((i = 16; i < 56; i++)); do
        OPTION_BYTES+=("${VALUE_TOKENS[$i]}")
    done
fi

echo
echo "Decoded packet profile:"
echo "  ttl: ${ttl}"
echo "  tos: 0x$(printf '%02x' "$tos")"
echo "  tcp_window: ${tcp_window}"
echo "  tcp_mss: ${tcp_mss}"
echo "  tcp_window_scale: ${tcp_window_scale}"
echo "  randomize_tcp_timestamp: ${randomize_tcp_timestamp}"
echo "  randomize_ipv4_id: ${randomize_ipv4_id}"
echo "  randomize_ipv6_flow: ${randomize_ipv6_flow}"
echo "  options_len: ${options_len}"
echo "  mss_value_offset: ${mss_value_offset}"
echo "  tsval_value_offset: ${tsval_value_offset}"
echo "  window_scale_value_offset: ${window_scale_value_offset}"
echo "  option_bytes: $(join_by ' ' "${OPTION_BYTES[@]:0:$options_len}")"
echo "  option_layout: $(decode_tcp_options OPTION_BYTES "$options_len")"

if [[ "$ttl" -eq 0 && "$tos" -eq 0 && "$tcp_window" -eq 0 && "$tcp_mss" -eq 0 && "$tcp_window_scale" -eq 0 && "$options_len" -eq 0 ]]; then
    echo
    echo "Pinned packet profile state: map is pinned but still unsynced"
    echo "STATIC only writes this map on startup and when /profiles/select changes the active profile."
    echo "For local WSL development, cargo run is usually not enough here because BPF_OBJ_GET still requires kernel capabilities even when the pinned map is owned by your user."
    echo "Use scripts/run-static-with-ebpf-caps.sh after verify-ebpf-attach.sh so the STATIC process runs as your user with the needed BPF capabilities."
fi

echo
echo "== Protocol counter map =="
protocol_counter_id=$(map_id_by_name protocol_counter)
if [[ -n "${protocol_counter_id}" ]]; then
    "${SUDO[@]}" bpftool map dump id "$protocol_counter_id"
else
    echo "protocol_counter map not found"
fi