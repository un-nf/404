# 404 v.02 - eBPF TTL Editor

Packet-level fingerprint manipulation using eBPF and Linux TC.

## What does this do?

This program attaches to the Linux TC egress hook and rewrites outgoing packet fields that are commonly used for passive OS and network stack fingerprinting. It aligns packet-layer traits with the browser profile selected by `STATIC`, so network-visible behavior stays consistent with the browser, TLS, and JavaScript fingerprint surfaces being presented at higher layers.

The classifier applies profile-driven changes to:

- IPv4 TTL, TOS, and IP ID
- IPv6 hop limit, traffic class, and flow label
- TCP window size
- TCP SYN option layout and values, including MSS, window scale, and optional timestamp values

## Why this exists

Operating systems expose distinct TCP/IP defaults. Windows, Linux, and macOS differ in TTL, window sizing, window scale, timestamp behavior, and SYN option ordering. Those differences are easy to observe with tools such as `p0f` or `nmap`, and they remain visible even when HTTP headers, TLS behavior, and browser APIs are being spoofed successfully.

Keeping the transport layer aligned with the selected browser persona reduces cross-layer mismatches that can be used to identify automation or synthetic traffic.

## Profile model

Packet settings are described by a `fingerprint_profile` map entry in the kernel and a matching `PacketProfile` struct in `STATIC`. The active browser profile is materialized from the selected browser profile JSON, including any seeded overlays, then converted into a packet profile and written into the pinned eBPF map at:

`/sys/fs/bpf/404/fingerprint_profiles`

The path can be overridden for testing with:

`STATIC_EBPF_MAP_PATH`

The Linux distro bootstrap mounts `bpffs`, attaches `ttl_editor.o` to `eth0`, and pins the map so the userspace STATIC process can update it at boot and whenever `/profiles/select` changes the active persona.

## Default fingerprints

Built-in defaults map to the selected platform family when a profile does not override packet values explicitly.

| OS | TTL | Window Size | Window Scale | MSS | Timestamps | TCP Option Order |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Windows | 128 | 64240 | 8 | 1460 | Disabled on SYN | MSS,NOP,WS,NOP,NOP,SACK |
| macOS | 64 | 65535 | 6 | 1460 | Enabled | MSS,NOP,WS,NOP,NOP,TS,SACK,EOL |
| Linux | 64 | 65535 | 7 | 1460 | Enabled | MSS,SACK,TS,NOP,WS |

Shipped Windows browser profiles also carry explicit `packet_profile` blocks and seeded packet overlays so non-critical device-like traits such as MSS and initial SYN window can vary across restarts while preserving the core platform shape.

## Build

Build on Linux or WSL with the required kernel headers and networking tools available:

```bash
$ make deps-install
$ make
```

Manual compilation:

```bash
$ clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86-linux-gnu -c ttl_editor.c -o ttl_editor.o
```

Dependencies:

- `clang`
- `llvm`
- `libbpf-dev`
- `linux-headers-$(uname -r)`
- `iproute2`

## Attach and remove

Attach to an interface such as `eth0` or `wlan0`:

```bash
$ sudo tc qdisc add dev <interface> clsact
$ sudo tc filter add dev <interface> egress bpf da obj ttl_editor.o sec classifier
```

Remove the classifier:

```bash
$ sudo tc filter del dev <interface> egress
$ sudo tc qdisc del dev <interface> clsact
```

## How it works

The classifier inspects each outgoing Ethernet frame, identifies IPv4 or IPv6 traffic, and applies profile-driven mutations in place.

For IPv4 it can:

- Rewrite TOS
- Randomize IP ID for non-fragmented packets
- Rewrite TTL
- Apply TCP window and SYN option changes

For IPv6 it can:

- Rewrite traffic class
- Randomize the flow label
- Rewrite hop limit
- Apply TCP window and SYN option changes

SYN option rewriting supports both fixed layouts and resized option blocks. When the TCP header length changes, the program adjusts packet length fields and updates TCP checksums explicitly so the rewritten packet remains valid after `bpf_skb_change_tail()` drops offload state.

## Verification

Confirm the classifier is attached:

```bash
$ sudo tc filter show dev <interface> egress
```

Confirm the pinned map exists:

```bash
$ sudo bpftool map show pinned /sys/fs/bpf/404/fingerprint_profiles
```

Inspect outbound SYN packets with `tcpdump`:

```bash
$ tcpdump -i <interface> -vvv -c 20 -Q out 'tcp[tcpflags] & tcp-syn != 0'
$ tcpdump -i <interface> -vvv -nn -Q out | grep -E 'ttl|win|mss|wscale'
$ tcpdump -i <interface> -vvv -XX -Q out port 443
```

![tcpdump output](https://raw.githubusercontent.com/un-nf/404/refs/heads/main/.github/IMAGES/tcpdump_output.png "tcpdump output")

## Limitations

- **Linux only**: eBPF and TC are Linux kernel features.
- **Requires a kernel with the needed TC/eBPF helpers**: the classifier relies on helpers such as `bpf_skb_change_tail`, `bpf_csum_diff`, and `bpf_l4_csum_replace`.
- **Requires root or `CAP_NET_ADMIN`**: attaching classifiers and pinning maps needs elevated privileges.
- **Egress only**: ingress-side fingerprinting remains outside this hook.
- **Focused on IP and TCP traits**: it does not model every packet type or every transport-layer behavior.
- **SYN payload rewrites are limited**: SYN packets carrying payload are not resized.

## Configuration

Packet behavior is configured through the profile JSON that STATIC loads, not by editing compile-time constants for normal use. A profile may include a `packet_profile` block with fields such as:

- `ttl`
- `tos`
- `tcp_window`
- `tcp_mss`
- `tcp_window_scale`
- `randomize_tcp_timestamp`
- `randomize_ipv4_id`
- `randomize_ipv6_flow`
- `options`

The `options` field is an ordered array of symbolic TCP option tokens. Supported tokens are:

- `mss`
- `nop`
- `window_scale` or `ws`
- `sack_permitted` or `sack`
- `timestamp`, `timestamps`, or `ts`
- `eol`

Packet overlays can be merged through `seeded_overlays`, which allows a profile family to keep a stable platform fingerprint while varying secondary device-like transport traits across process lifetimes.

## References

- eBPF: https://ebpf.io/
- TC (Traffic Control): https://man7.org/linux/man-pages/man8/tc.8.html
- `tc-bpf(8)`: https://man7.org/linux/man-pages/man8/tc-bpf.8.html
- p0f: https://lcamtuf.coredump.cx/p0f3/
- nmap OS detection: https://nmap.org/book/osdetect.html