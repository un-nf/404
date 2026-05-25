/* TCP/IP fingerpint editor

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Compile with:

    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/ -I/usr/include/linux -c TTLEDIT-STABLE.c -o <output>.o

*/

/* Attach with:

    sudo tc qdisc add dev <interface> clsact
    sudo tc filter add dev <interface> egress bpf da obj <output>.o sec classifier

*/

/* Remove with:

    sudo tc filter del dev <interface> egress
    sudo tc qdisc del dev <interface> clsact

*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} protocol_counter SEC(".maps");

struct fingerprint_profile {
    __u8 ttl;
    __u8 tos;
    __u16 tcp_window;
    __u16 tcp_mss;
    __u8 tcp_window_scale;
    __u8 randomize_tcp_timestamp;
    __u8 randomize_ipv4_id;
    __u8 randomize_ipv6_flow;
    __u8 options_len;
    __u8 mss_value_offset;
    __u8 tsval_value_offset;
    __u8 window_scale_value_offset;
    __u8 reserved[4];
    __u8 options[40];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fingerprint_profile);
} fingerprint_profiles SEC(".maps");

#define FORCE_TTL 128
#define SPOOF_TCP_WINDOW_SIZE 64240
#define SPOOF_TCP_WINDOW_SCALE 8
#define SPOOF_TCP_MSS 1460
#define SPOOF_IP_TOS 0x10
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_HEADER_BYTES 20
#define TCP_MAX_OPTIONS_BYTES 40
#define INVALID_OPTION_OFFSET 0xFF

#define SPOOF_IP_ID_ENABLE 1
#define SPOOF_IPV6_FLOW_ENABLE 1
#define RANDOMIZE_TCP_TIMESTAMP 0

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW_SCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_TIMESTAMP 8

const int RETURN_CODE = TC_ACT_OK;

struct tcphdr_min {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 doff_res;
    __u8 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

static __always_inline int parse_ipv4(void *data, void *data_end)
{
    struct iphdr *ip_header = data;

    if ((void *)&ip_header[1] > data_end) {
        return 0;
    }

    return ip_header->protocol;
}

static __always_inline int parse_ipv6(void *data, void *data_end)
{
    struct ipv6hdr *ip6_header = data;

    if ((void *)&ip6_header[1] > data_end) {
        return 0;
    }

    return ip6_header->nexthdr;
}

static __always_inline int store_bytes_recompute(struct __sk_buff *skb, __u32 offset, const void *src, __u32 len)
{
    return bpf_skb_store_bytes(skb, offset, src, len, BPF_F_RECOMPUTE_CSUM);
}

static __always_inline int store_bytes_plain(struct __sk_buff *skb, __u32 offset, const void *src, __u32 len)
{
    return bpf_skb_store_bytes(skb, offset, src, len, 0);
}

static __always_inline int apply_tcp_checksum_diff(struct __sk_buff *skb, __u32 tcp_offset, __s64 diff, __u64 flags)
{
    if (diff == 0) {
        return 0;
    }

    return bpf_l4_csum_replace(
        skb,
        tcp_offset + offsetof(struct tcphdr_min, check),
        0,
        (__u64)diff,
        flags
    );
}

static __always_inline int sync_tcp_pseudo_length(
    struct __sk_buff *skb,
    __u16 h_proto,
    __u32 tcp_offset,
    __u16 old_tcp_length,
    __u16 new_tcp_length
)
{
    if (old_tcp_length == new_tcp_length) {
        return 0;
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        __be16 old_be = bpf_htons(old_tcp_length);
        __be16 new_be = bpf_htons(new_tcp_length);

        return bpf_l4_csum_replace(
            skb,
            tcp_offset + offsetof(struct tcphdr_min, check),
            old_be,
            new_be,
            BPF_F_PSEUDO_HDR | sizeof(new_be)
        );
    }

    if (h_proto == __constant_htons(ETH_P_IPV6)) {
        __be32 old_be = bpf_htonl((__u32)old_tcp_length);
        __be32 new_be = bpf_htonl((__u32)new_tcp_length);

        return bpf_l4_csum_replace(
            skb,
            tcp_offset + offsetof(struct tcphdr_min, check),
            old_be,
            new_be,
            BPF_F_PSEUDO_HDR | sizeof(new_be)
        );
    }

    return -1;
}

static __always_inline int store_ipv4_field(
    struct __sk_buff *skb,
    __u32 field_offset,
    __u32 checksum_offset,
    __u16 old_value,
    __u16 new_value
)
{
    __be16 old_be = bpf_htons(old_value);
    __be16 new_be = bpf_htons(new_value);

    if (old_be == new_be) {
        return 0;
    }

    if (bpf_l3_csum_replace(skb, checksum_offset, old_be, new_be, sizeof(new_be)) != 0) {
        return -1;
    }

    return bpf_skb_store_bytes(skb, field_offset, &new_be, sizeof(new_be), 0);
}

static __always_inline int sync_ipv4_tos(
    struct __sk_buff *skb,
    __u32 network_header_offset,
    const struct iphdr *ip_header,
    __u8 new_tos
)
{
    __u16 old_pair = (((__u16)ip_header->version << 12) | ((__u16)ip_header->ihl << 8) | ip_header->tos);
    __u16 new_pair = (((__u16)ip_header->version << 12) | ((__u16)ip_header->ihl << 8) | new_tos);

    return store_ipv4_field(
        skb,
        network_header_offset,
        network_header_offset + offsetof(struct iphdr, check),
        old_pair,
        new_pair
    );
}

static __always_inline int sync_ipv4_ttl(
    struct __sk_buff *skb,
    __u32 network_header_offset,
    const struct iphdr *ip_header,
    __u8 new_ttl
)
{
    __u16 old_pair = (((__u16)ip_header->ttl) << 8) | ip_header->protocol;
    __u16 new_pair = (((__u16)new_ttl) << 8) | ip_header->protocol;

    return store_ipv4_field(
        skb,
        network_header_offset + offsetof(struct iphdr, ttl),
        network_header_offset + offsetof(struct iphdr, check),
        old_pair,
        new_pair
    );
}

static __always_inline int sync_ipv4_id(
    struct __sk_buff *skb,
    __u32 network_header_offset,
    const struct iphdr *ip_header,
    __u16 new_id
)
{
    return store_ipv4_field(
        skb,
        network_header_offset + offsetof(struct iphdr, id),
        network_header_offset + offsetof(struct iphdr, check),
        bpf_ntohs(ip_header->id),
        new_id
    );
}

static __always_inline int sync_ipv4_total_length(
    struct __sk_buff *skb,
    __u32 network_header_offset,
    const struct iphdr *ip_header,
    __u16 new_total_length
)
{
    return store_ipv4_field(
        skb,
        network_header_offset + offsetof(struct iphdr, tot_len),
        network_header_offset + offsetof(struct iphdr, check),
        bpf_ntohs(ip_header->tot_len),
        new_total_length
    );
}

static __always_inline int resize_tcp_header_for_syn(
    struct __sk_buff *skb,
    void *data,
    void *data_end,
    __u16 h_proto,
    __u32 network_header_offset,
    __u32 tcp_offset,
    __u32 current_options_len,
    __u32 target_options_len
)
{
    __s32 delta = (__s32)target_options_len - (__s32)current_options_len;

    if (delta == 0) {
        return 0;
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip_header = data + network_header_offset;
        __u8 ihl;
        __u16 total_length;
        __u32 tcp_header_len;
        __u32 payload_len;

        if ((void *)&ip_header[1] > data_end) {
            return -1;
        }

        ihl = ip_header->ihl;
        if (ihl < 5 || ihl > 15) {
            return -1;
        }

        total_length = bpf_ntohs(ip_header->tot_len);
        tcp_header_len = TCP_HEADER_BYTES + current_options_len;
        if (total_length < ((__u16)ihl * 4) + tcp_header_len) {
            return -1;
        }

        payload_len = total_length - ((__u16)ihl * 4) - tcp_header_len;
        if (payload_len != 0) {
            return -1;
        }

        if (bpf_skb_change_tail(skb, (__u32)((__s32)skb->len + delta), 0) != 0) {
            return -1;
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip_header = data + network_header_offset;
        if ((void *)&ip_header[1] > data_end) {
            return -1;
        }

        if (sync_ipv4_total_length(skb, network_header_offset, ip_header, (__u16)((__s32)total_length + delta)) != 0) {
            return -1;
        }

        return 0;
    }

    if (h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6_header = data + network_header_offset;
        __u16 payload_length;
        __u32 tcp_header_len;
        __u32 payload_len;
        __be16 new_payload_length;

        if ((void *)&ip6_header[1] > data_end) {
            return -1;
        }

        payload_length = bpf_ntohs(ip6_header->payload_len);
        tcp_header_len = TCP_HEADER_BYTES + current_options_len;
        if (payload_length < tcp_header_len) {
            return -1;
        }

        payload_len = payload_length - tcp_header_len;
        if (payload_len != 0) {
            return -1;
        }

        if (bpf_skb_change_tail(skb, (__u32)((__s32)skb->len + delta), 0) != 0) {
            return -1;
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip6_header = data + network_header_offset;
        if ((void *)&ip6_header[1] > data_end) {
            return -1;
        }

        new_payload_length = bpf_htons((__u16)((__s32)payload_length + delta));
        return bpf_skb_store_bytes(
            skb,
            network_header_offset + offsetof(struct ipv6hdr, payload_len),
            &new_payload_length,
            sizeof(new_payload_length),
            0
        );
    }

    return -1;
}

static __always_inline int rewrite_syn_options(
    struct __sk_buff *skb,
    void *data,
    void *data_end,
    __u16 h_proto,
    __u32 network_header_offset,
    __u32 tcp_offset,
    const struct fingerprint_profile *profile
)
{
    struct tcphdr_min *tcp = data + tcp_offset;
    __u32 old_option_words[TCP_MAX_OPTIONS_BYTES / sizeof(__u32)] = {};
    __u32 rewritten_words[TCP_MAX_OPTIONS_BYTES / sizeof(__u32)] = {};
    __u8 *old_options = (__u8 *)old_option_words;
    __u8 *rewritten = (__u8 *)rewritten_words;
    __u8 doff;
    __u8 old_doff_res;
    __u8 old_flags;
    __u32 options_offset;
    __u32 options_len;
    __u16 old_tcp_length;
    __u8 new_doff_res;
    __be16 old_doff_flags;
    __be16 new_doff_flags;
    __s64 options_diff;

    if ((void *)&tcp[1] > data_end) {
        return 0;
    }

    doff = (tcp->doff_res >> 4) & 0x0F;
    if (doff < 5) {
        return 0;
    }

    options_len = (doff * 4) - TCP_HEADER_BYTES;
    if (options_len == 0 || options_len > TCP_MAX_OPTIONS_BYTES) {
        return 0;
    }

    if (profile->options_len == 0 || profile->options_len > TCP_MAX_OPTIONS_BYTES || (profile->options_len & 0x3) != 0) {
        return 0;
    }

    old_doff_res = tcp->doff_res;
    old_flags = tcp->flags;
    old_tcp_length = TCP_HEADER_BYTES + options_len;

    if (bpf_skb_load_bytes(skb, tcp_offset + TCP_HEADER_BYTES, old_options, options_len) != 0) {
        return 0;
    }

    if (profile->options_len != options_len) {
        if (resize_tcp_header_for_syn(
            skb,
            data,
            data_end,
            h_proto,
            network_header_offset,
            tcp_offset,
            options_len,
            profile->options_len
        ) != 0) {
            return 0;
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        tcp = data + tcp_offset;
        if ((void *)&tcp[1] > data_end) {
            return 0;
        }

        doff = (TCP_HEADER_BYTES + profile->options_len) / 4;
        options_len = profile->options_len;

        if (sync_tcp_pseudo_length(skb, h_proto, tcp_offset, old_tcp_length, TCP_HEADER_BYTES + options_len) != 0) {
            return 0;
        }
    }

    new_doff_res = (old_doff_res & 0x0F) | (doff << 4);

    #pragma unroll
    for (__u32 i = 0; i < TCP_MAX_OPTIONS_BYTES; i++) {
        if (i >= options_len) {
            break;
        }

        if (i < profile->options_len) {
            rewritten[i] = profile->options[i];
        } else if (i == profile->options_len) {
            rewritten[i] = TCPOPT_EOL;
        } else {
            rewritten[i] = TCPOPT_NOP;
        }
    }

    if (profile->mss_value_offset != INVALID_OPTION_OFFSET && profile->mss_value_offset + 2 <= options_len) {
        __be16 mss_be = bpf_htons(profile->tcp_mss);
        __builtin_memcpy(&rewritten[profile->mss_value_offset], &mss_be, sizeof(mss_be));
    }

    if (profile->window_scale_value_offset != INVALID_OPTION_OFFSET && profile->window_scale_value_offset < options_len) {
        rewritten[profile->window_scale_value_offset] = profile->tcp_window_scale;
    }

    if (
        profile->randomize_tcp_timestamp &&
        profile->tsval_value_offset != INVALID_OPTION_OFFSET &&
        profile->tsval_value_offset + 3 < options_len
    ) {
        __u32 tsval = (__u32)(bpf_ktime_get_ns() >> 10);
        __be32 tsval_be = bpf_htonl(tsval);
        __builtin_memcpy(&rewritten[profile->tsval_value_offset], &tsval_be, sizeof(tsval_be));
    }

    options_offset = tcp_offset + TCP_HEADER_BYTES;

    if (new_doff_res != old_doff_res) {
        __u32 doff_offset = tcp_offset + offsetof(struct tcphdr_min, doff_res);

        old_doff_flags = bpf_htons((((__u16)old_doff_res) << 8) | old_flags);
        new_doff_flags = bpf_htons((((__u16)new_doff_res) << 8) | old_flags);

        if (store_bytes_plain(skb, doff_offset, &new_doff_res, sizeof(new_doff_res)) != 0) {
            return 0;
        }

        if (bpf_l4_csum_replace(
            skb,
            tcp_offset + offsetof(struct tcphdr_min, check),
            old_doff_flags,
            new_doff_flags,
            sizeof(new_doff_flags)
        ) != 0) {
            return 0;
        }
    }

    if (store_bytes_plain(skb, options_offset, rewritten, options_len) != 0) {
        return 0;
    }

    options_diff = bpf_csum_diff((__be32 *)old_options, old_tcp_length - TCP_HEADER_BYTES, (__be32 *)rewritten, options_len, 0);
    if (options_diff < 0) {
        return 0;
    }

    return apply_tcp_checksum_diff(skb, tcp_offset, options_diff, 0);
}

static __always_inline void spoof_tcp_fingerprint(
    struct __sk_buff *skb,
    void *data,
    void *data_end,
    __u16 h_proto,
    __u32 network_header_offset,
    __u32 tcp_offset,
    const struct fingerprint_profile *profile
)
{
    struct tcphdr_min *tcp = data + tcp_offset;
    __u8 tcp_flags;
    int is_syn;

    if ((void *)&tcp[1] > data_end) {
        return;
    }

    tcp_flags = tcp->flags;
    is_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);

    if (tcp->window != bpf_htons(profile->tcp_window)) {
        __u32 window_offset = tcp_offset + offsetof(struct tcphdr_min, window);
        __be16 new_window_be = bpf_htons(profile->tcp_window);

        if (store_bytes_recompute(skb, window_offset, &new_window_be, sizeof(new_window_be)) != 0) {
            return;
        }
    }

    if (!is_syn) {
        return;
    }

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if (rewrite_syn_options(skb, data, data_end, h_proto, network_header_offset, tcp_offset, profile) != 0) {
        return;
    }
}

SEC("classifier")
int tc_counter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 profile_key = 0;
    struct fingerprint_profile profile = {
        .ttl = FORCE_TTL,
        .tos = SPOOF_IP_TOS,
        .tcp_window = SPOOF_TCP_WINDOW_SIZE,
        .tcp_mss = SPOOF_TCP_MSS,
        .tcp_window_scale = SPOOF_TCP_WINDOW_SCALE,
        .randomize_tcp_timestamp = RANDOMIZE_TCP_TIMESTAMP,
        .randomize_ipv4_id = SPOOF_IP_ID_ENABLE,
        .randomize_ipv6_flow = SPOOF_IPV6_FLOW_ENABLE,
        .options_len = 12,
        .mss_value_offset = 2,
        .tsval_value_offset = INVALID_OPTION_OFFSET,
        .window_scale_value_offset = 7,
        .options = {
            TCPOPT_MSS, 4, 0, 0,
            TCPOPT_NOP,
            TCPOPT_WINDOW_SCALE, 3, 0,
            TCPOPT_NOP,
            TCPOPT_NOP,
            TCPOPT_SACK_PERMITTED, 2,
        },
    };
    struct fingerprint_profile *configured_profile = bpf_map_lookup_elem(&fingerprint_profiles, &profile_key);
    struct ethhdr *eth = data;
    __u32 network_header_offset = sizeof(*eth);
    __u16 h_proto;
    int protocol_index = 0;

    if (configured_profile) {
        profile = *configured_profile;
    }

    if (data + network_header_offset > data_end) {
        return RETURN_CODE;
    }

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_IP)) {
        protocol_index = parse_ipv4(data + network_header_offset, data_end);
    } else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        protocol_index = parse_ipv6(data + network_header_offset, data_end);
    }

    if (protocol_index != 0) {
        __u32 key = (__u32)protocol_index;
        __u64 *protocol_count = bpf_map_lookup_elem(&protocol_counter, &key);

        if (protocol_count) {
            __sync_fetch_and_add(protocol_count, 1);
        }
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip_header;

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip_header = data + network_header_offset;

        if ((void *)&ip_header[1] > data_end) {
            return RETURN_CODE;
        }

        if (ip_header->tos != profile.tos) {
            if (sync_ipv4_tos(skb, network_header_offset, ip_header, profile.tos) != 0) {
                return RETURN_CODE;
            }

            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip_header = data + network_header_offset;
            if ((void *)&ip_header[1] > data_end) {
                return RETURN_CODE;
            }
        }

        if (profile.randomize_ipv4_id && !(bpf_ntohs(ip_header->frag_off) & 0x1FFF)) {
            __u16 new_id = (__u16)bpf_get_prandom_u32();

            if (sync_ipv4_id(skb, network_header_offset, ip_header, new_id) != 0) {
                return RETURN_CODE;
            }

            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip_header = data + network_header_offset;
            if ((void *)&ip_header[1] > data_end) {
                return RETURN_CODE;
            }
        }

        if (ip_header->ttl != profile.ttl) {
            if (sync_ipv4_ttl(skb, network_header_offset, ip_header, profile.ttl) != 0) {
                return RETURN_CODE;
            }

            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip_header = data + network_header_offset;
            if ((void *)&ip_header[1] > data_end) {
                return RETURN_CODE;
            }
        }

        if (ip_header->protocol == IPPROTO_TCP) {
            __u8 ihl = ip_header->ihl;
            __u32 tcp_offset;

            if (ihl < 5 || ihl > 15) {
                return RETURN_CODE;
            }

            tcp_offset = network_header_offset + (ihl * 4);
            spoof_tcp_fingerprint(skb, data, data_end, h_proto, network_header_offset, tcp_offset, &profile);
        }
    }

    if (h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6_header;

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip6_header = data + network_header_offset;

        if ((void *)&ip6_header[1] > data_end) {
            return RETURN_CODE;
        }

        {
            __be32 *vtf_ptr = (__be32 *)ip6_header;
            __u32 desired_flow;

            if ((void *)(vtf_ptr + 1) > data_end) {
                return RETURN_CODE;
            }

            {
                __u32 old_vtf = bpf_ntohl(*vtf_ptr);
                __u32 old_flow = old_vtf & 0x000FFFFF;
                __u32 new_vtf;

                desired_flow = profile.randomize_ipv6_flow ? (bpf_get_prandom_u32() & 0x000FFFFF) : old_flow;
                new_vtf = (6U << 28) | (((__u32)profile.tos) << 20) | desired_flow;

                if (new_vtf != old_vtf) {
                    __be32 new_vtf_be = bpf_htonl(new_vtf);

                    if (bpf_skb_store_bytes(skb, network_header_offset, &new_vtf_be, sizeof(new_vtf_be), 0) != 0) {
                        return RETURN_CODE;
                    }
                }
            }

            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip6_header = data + network_header_offset;
            if ((void *)&ip6_header[1] > data_end) {
                return RETURN_CODE;
            }
        }

        if (ip6_header->hop_limit != profile.ttl) {
            __u32 hop_limit_offset = network_header_offset + offsetof(struct ipv6hdr, hop_limit);

            if (bpf_skb_store_bytes(skb, hop_limit_offset, &profile.ttl, sizeof(profile.ttl), 0) != 0) {
                return RETURN_CODE;
            }

            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            ip6_header = data + network_header_offset;
            if ((void *)&ip6_header[1] > data_end) {
                return RETURN_CODE;
            }
        }

        if (ip6_header->nexthdr == IPPROTO_TCP) {
            __u32 tcp_offset = network_header_offset + sizeof(struct ipv6hdr);
            spoof_tcp_fingerprint(skb, data, data_end, h_proto, network_header_offset, tcp_offset, &profile);
        }
    }

    return RETURN_CODE;
}

char LICENSE[] SEC("license") = "GPL";
