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
#include <stddef.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
    __type(value, long);
} protocol_counter SEC(".maps");

#define FORCE_TTL 255
#define SPOOF_TCP_WINDOW_SIZE 65535      
#define SPOOF_TCP_INITIAL_SEQ 0x12345678           
#define SPOOF_TCP_WINDOW_SCALE 5
/* Most common MSS - for MTU 1500. 

Though, may need to lower if overhead due to VPN/tunneling to prevent packet dropping. Intelligent handling to come.

Mobile carriers: 

    Verizon: 1388
    T-Mobile: 1360
    Google Fi: 1348
    Bell Canada: 1420

*/    
#define SPOOF_TCP_MSS 1460
#define SPOOF_IP_TOS 0x10
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10


#define RANDOMIZE_SEQ_ENABLE 1 
#define SPOOF_IP_ID_ENABLE 1
#define SPOOF_IPV6_FLOW_ENABLE 1
// Windows does not use timestamps in its TCP fingerprint. All Unix based OSes do. Dynamic handling to come.
#define RANDOMIZE_TCP_TIMESTAMP 1 

// TCP Options kind no. mapping - Order varies by OS, fingerprint WILL leak due to TCP Options ordering. Not handled as of now. Patch to come. 
// iOS ends with TCP Option 0 (End of List) - Not handled
#define TCPOPT_NOP 1
#define TCPOPT_EOL 0
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW_SCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_TIMESTAMP 8

const int RETURN_CODE = TC_ACT_OK;

static __always_inline int parse_ipv4(void *data, void *data_end);
static __always_inline int parse_ipv6(void *data, void *data_end);
static __always_inline void spoof_tcp_fingerprint(struct __sk_buff *skb, void *data, void *data_end, __u32 tcp_offset);

SEC("classifier")

int tc_counter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    __u32 network_header_offset = sizeof(*eth);

    if (data + network_header_offset > data_end)
        return RETURN_CODE;

    __u16 h_proto = eth->h_proto;
    int protocol_index = 0;

    if (h_proto == __constant_htons(ETH_P_IP)) {
        protocol_index = parse_ipv4(data + network_header_offset, data_end);
    } else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        protocol_index = parse_ipv6(data + network_header_offset, data_end);
    } else {
        protocol_index = 0;
    }

    if (protocol_index == 0)
        return RETURN_CODE;

    __u32 key = (__u32)protocol_index;
    long *protocol_count = bpf_map_lookup_elem(&protocol_counter, &key);
    if (protocol_count) {
        __sync_fetch_and_add(protocol_count, 1);
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct iphdr *ip_header = data + network_header_offset;

        if ((void *)&ip_header[1] <= data_end) {
            __u8 old_ttl = ip_header->ttl;
            __u8 new_ttl = (__u8)FORCE_TTL;
            __u8 ip_protocol = ip_header->protocol;
            __u8 old_tos = ip_header->tos;
            __u16 old_id = bpf_ntohs(ip_header->id);

            if (old_tos != SPOOF_IP_TOS) {
                __u32 tos_offset = network_header_offset + offsetof(struct iphdr, tos);
                __u8 new_tos = SPOOF_IP_TOS;
                bpf_skb_store_bytes(skb, tos_offset, &new_tos, 1, 0);

                // Re-fetch after modification (do this a lot, more than you would think)
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            if (SPOOF_IP_ID_ENABLE && !(bpf_ntohs(ip_header->frag_off) & 0x1FFF)) {
                __u64 timestamp = bpf_ktime_get_ns();
                __u16 new_id = (__u16)(timestamp ^ (timestamp >> 16) ^ old_id);
                __u32 id_offset = network_header_offset + offsetof(struct iphdr, id);
                __be16 new_id_be = bpf_htons(new_id);
                bpf_skb_store_bytes(skb, id_offset, &new_id_be, 2, 0);

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            if (old_ttl != new_ttl) {

                int current_len = skb->len;

                if (bpf_skb_change_tail(skb, current_len, 0) != 0) {
                    return TC_ACT_SHOT;  
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u32 ttl_offset = network_header_offset + offsetof(struct iphdr, ttl);
                if (bpf_skb_store_bytes(skb, ttl_offset, &new_ttl, 1, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] <= data_end) {

                    ip_header->check = 0;

                    __u32 csum = 0;
                    __u16 *buf = (__u16 *)ip_header;
                    __u8 ihl = ip_header->ihl;

                    if (ihl < 5) ihl = 5;
                    if (ihl > 15) ihl = 15;

                    __u32 words = ihl * 2;

                    #pragma unroll
                    for (__u32 i = 0; i < 30; i++) {
                        if (i >= words) break;
                        if ((void *)(buf + i + 1) > data_end) break;
                        csum += bpf_ntohs(buf[i]);
                    }

                    csum = (csum & 0xFFFF) + (csum >> 16);
                    csum = (csum & 0xFFFF) + (csum >> 16);
                    ip_header->check = bpf_htons((__u16)~csum);
                }
            }

            if (ip_protocol == IPPROTO_TCP) {

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip_header = data + network_header_offset;

                if ((void *)&ip_header[1] <= data_end) {
                    __u8 ihl = ip_header->ihl;
                    if (ihl < 5) ihl = 5;
                    if (ihl > 15) ihl = 15;
                    __u32 tcp_offset = network_header_offset + (ihl * 4);
                    spoof_tcp_fingerprint(skb, data, data_end, tcp_offset);
                }
            }
        }
    }

    if (h_proto == __constant_htons(ETH_P_IPV6)) {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct ipv6hdr *ip6_header = data + network_header_offset;

        if ((void *)&ip6_header[1] <= data_end) {
            __u8 old_hl = ip6_header->hop_limit;
            __u8 new_hl = (__u8)FORCE_TTL;
            __u32 old_flow = bpf_ntohl(ip6_header->flow_lbl[0] | 
                                       (ip6_header->flow_lbl[1] << 8) | 
                                       (ip6_header->flow_lbl[2] << 16));

            if (SPOOF_IPV6_FLOW_ENABLE) {
                __u64 timestamp = bpf_ktime_get_ns();
                __u32 new_flow = (__u32)(timestamp ^ (timestamp >> 20)) & 0x000FFFFF;  

                __u32 version_tc = (ip6_header->priority << 4) | (ip6_header->flow_lbl[0] & 0xF0);
                __u32 new_vtf = (6 << 28) | (version_tc << 20) | new_flow;
                __be32 new_vtf_be = bpf_htonl(new_vtf);

                __u32 vtf_offset = network_header_offset + 0;  
                bpf_skb_store_bytes(skb, vtf_offset, &new_vtf_be, 4, 0);

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }
            }

            if (old_hl != new_hl) {

                int current_len = skb->len;

                if (bpf_skb_change_tail(skb, current_len, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u32 hl_offset = network_header_offset + offsetof(struct ipv6hdr, hop_limit);
                if (bpf_skb_store_bytes(skb, hl_offset, &new_hl, 1, 0) != 0) {
                    return TC_ACT_SHOT;
                }

                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                ip6_header = data + network_header_offset;

                if ((void *)&ip6_header[1] > data_end) {
                    return TC_ACT_SHOT;
                }

                __u8 next_header = ip6_header->nexthdr;
                if (next_header == IPPROTO_UDP) {
                    __u32 udp_offset = network_header_offset + sizeof(struct ipv6hdr);

                    __u32 udp_csum_offset = udp_offset + 6;

                    if ((void *)(data + udp_offset + 8) <= data_end) {
                        __u16 zero_csum = 0;
                        bpf_skb_store_bytes(skb, udp_csum_offset, &zero_csum, 2, 0);
                    }
                } else if (next_header == IPPROTO_TCP) {
                    __u32 tcp_offset = network_header_offset + sizeof(struct ipv6hdr);
                    spoof_tcp_fingerprint(skb, data, data_end, tcp_offset);
                }
            }
        }
    }

    return RETURN_CODE;
}

static __always_inline int parse_ipv4(void *ip_data, void *data_end)
{
    struct iphdr *ip_header = ip_data;
    if ((void *)&ip_header[1] > data_end)
        return 0;
    return ip_header->protocol;
}

static __always_inline int parse_ipv6(void *ipv6_data, void *data_end)
{
    struct ipv6hdr *ip6_header = ipv6_data;
    if ((void *)&ip6_header[1] > data_end)
        return 0;
    return ip6_header->nexthdr;
}

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

static __always_inline void spoof_tcp_fingerprint(struct __sk_buff *skb, void *data, void *data_end, __u32 tcp_offset)
{

    struct tcphdr_min *tcp = data + tcp_offset;
    if ((void *)&tcp[1] > data_end) {
        return;
    }

    __u8 tcp_flags = tcp->flags;
    __u32 old_seq = bpf_ntohl(tcp->seq);
    __u16 old_window = bpf_ntohs(tcp->window);

    int is_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);

    __u16 new_window = SPOOF_TCP_WINDOW_SIZE;
    if (old_window != new_window) {
        __u32 window_offset = tcp_offset + offsetof(struct tcphdr_min, window);
        __be16 new_window_be = bpf_htons(new_window);
        bpf_skb_store_bytes(skb, window_offset, &new_window_be, 2, 0);
    }

    if (is_syn) {
        __u32 new_seq;
        if (RANDOMIZE_SEQ_ENABLE) {

            __u64 timestamp = bpf_ktime_get_ns();
            new_seq = (__u32)(timestamp ^ (timestamp >> 32) ^ old_seq ^ SPOOF_TCP_INITIAL_SEQ);
        } else {
            new_seq = SPOOF_TCP_INITIAL_SEQ;
        }
        if (old_seq != new_seq) {
            __u32 seq_offset = tcp_offset + offsetof(struct tcphdr_min, seq);
            __be32 new_seq_be = bpf_htonl(new_seq);
            bpf_skb_store_bytes(skb, seq_offset, &new_seq_be, 4, 0);
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        tcp = data + tcp_offset;
        if ((void *)&tcp[1] > data_end) {
            return;
        }

        __u8 doff = (tcp->doff_res >> 4) & 0x0F;  
        if (doff < 5) doff = 5;
        if (doff > 15) doff = 15;
        __u32 tcp_header_len = doff * 4;
        __u32 options_len = tcp_header_len - sizeof(struct tcphdr_min);
        if (options_len > 0 && options_len <= 40) {
            __u32 opt_offset = tcp_offset + sizeof(struct tcphdr_min);
            __u8 *opt_ptr = data + opt_offset;
            #pragma unroll
            for (__u32 i = 0; i < 40; i++) {
                if (i >= options_len) break;
                __u8 *current_opt = opt_ptr + i;
                if ((void *)(current_opt + 1) > data_end) break;
                __u8 opt_kind = *current_opt;
                if (opt_kind == TCPOPT_EOL) break;
                if (opt_kind == TCPOPT_NOP) continue;
                if ((void *)(current_opt + 2) > data_end) break;
                __u8 opt_len = *(current_opt + 1);
                if (opt_len < 2 || opt_len > 40) break;
                if (i + opt_len > options_len) break;

                if (opt_kind == TCPOPT_MSS && opt_len == 4) {
                    if ((void *)(current_opt + 4) > data_end) break;
                    __u16 new_mss = SPOOF_TCP_MSS;
                    __be16 new_mss_be = bpf_htons(new_mss);
                    __u32 mss_offset = opt_offset + i + 2;
                    bpf_skb_store_bytes(skb, mss_offset, &new_mss_be, 2, 0);

                    data = (void *)(long)skb->data;
                    data_end = (void *)(long)skb->data_end;
                    opt_ptr = data + opt_offset;
                }

                if (opt_kind == TCPOPT_WINDOW_SCALE && opt_len == 3) {
                    if ((void *)(current_opt + 3) > data_end) break;
                    __u8 old_wscale = *(current_opt + 2);
                    __u8 new_wscale = SPOOF_TCP_WINDOW_SCALE;
                    if (old_wscale != new_wscale) {
                        __u32 wscale_offset = opt_offset + i + 2;
                        bpf_skb_store_bytes(skb, wscale_offset, &new_wscale, 1, 0);

                        data = (void *)(long)skb->data;
                        data_end = (void *)(long)skb->data_end;
                        opt_ptr = data + opt_offset;
                    }
                }

                if (opt_kind == TCPOPT_TIMESTAMP && opt_len == 10 && RANDOMIZE_TCP_TIMESTAMP) {
                    if ((void *)(current_opt + 10) > data_end) break;
                    __u64 timestamp = bpf_ktime_get_ns();
                    __u32 new_tsval = (__u32)(timestamp >> 10);
                    __be32 new_tsval_be = bpf_htonl(new_tsval);
                    __u32 tsval_offset = opt_offset + i + 2;
                    bpf_skb_store_bytes(skb, tsval_offset, &new_tsval_be, 4, 0);

                    data = (void *)(long)skb->data;
                    data_end = (void *)(long)skb->data_end;
                    opt_ptr = data + opt_offset;
                }
                i += opt_len - 1;
            }
        }
    }

}

char LICENSE[] SEC("license") = "GPL";