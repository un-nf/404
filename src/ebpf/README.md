# 404 v.02 - eBPF TTL Editor

Packet-level fingerprint manipulation using eBPF (Extended Berkeley Packet Filter) and Linux TC (Traffic Control).

## What does this do?

This eBPF program hooks into the Linux kernel's network stack at the TC egress point and modifies outgoing packets before they leave your machine. It rewrites packet-level fingerprints that are visible to network observers and can be used to identify your OS and network stack implementation.

## Build

```bash
$ make deps-install  # shows dependency installation command
$ make               # compiles ttl_editor.o
$
$ # Manual compilation
$ clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/ -I/usr/include/linux -c TTLEDIT-STABLE.c -o <output>.o

```
 
Dependencies: `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`, `iproute2`

## Usage

Attach to network interface (replace `<interface>` with `eth0`, `wlan0`, etc.):

```bash
$ sudo tc qdisc add dev <interface> clsact
$ sudo tc filter add dev <interface> egress bpf da obj ttl_editor.o sec classifier
```
 
Remove:

```bash
$ sudo tc filter del dev <interface> egress
$ sudo tc qdisc del dev <interface> clsact
```

**Modifications:**

Currently, IP/TCP packet header values are assigned via global variables at the top of `ttl_editor.c`.

**IPv4:**
- TTL (Time To Live) → forced to 255
- TOS (Type of Service) → set to 0x10
- IP ID (Identification) → randomized per packet
- TCP window size → 65535
- TCP initial sequence number → randomized (again)
- TCP window scale → 5
- TCP MSS (Maximum Segment Size) → 1460
- TCP timestamps → randomized

**IPv6:**
- Hop limit → forced to 255
- Flow label → randomized
- TCP parameters (same as IPv4)

### Limitations:

In its current state, this eBPF program does *not* map to the values being passed from `profiles.json`. This is a *major* pitfall of the current version. Future patch will fix this. This eBPF program serves as POC.

*Many packet types and their headers are not handled.*

> A common list of TCP/IP fingeprinting methods can be found at this [nmap source](https://nmap.org/book/osdetect-methods.html).

#### For now:

Default OS network stack fingerprints:

| OS | TTL | Window Size | Window Scale | ISN | MSS* | Timestamps | TCP Option Order |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Windows | 128 | 64 kb (64240 bytes) | 8 | Randomized | Varies based on connection | Not used | MSS,NOP,WS,NOP,NOP,SACK |
| MacOS | 64 | 64 kb (65535 bytes) | 6 | Randomized | Varies based on connection | Internal counter | MSS,NOP,WS,NOP,NOP,TS,SACK,EOL |
| Linux | 64 | 64 kb (65535 bytes - 5840 bytes for 2.4/2.6 kernels) | 7 | Randomized | Varies based on connection | Internal counter - sometimes randomized | MSS,SACK,TS,NOP,WS |

## So... why?

Operating systems have distinct network stack implementations. Windows, Linux, macOS, Android, and iOS set different default values for TCP/IP packet headers (TTL, MSS, WinSize/Scale). These fingerprinting vectors are trivial to collect and can identify your OS even if you spoof your HTTP headers and browser fingerprint perfectly. Tools like nmap and p0f allow third party network observers to exploit this fingerprinting vector.

> Mismatches between network, JS, and HTTPS values can also be used by servers to identify bot-likely traffic and block connections. 

Tools like `p0f` and `nmap` can passively fingerprint an OS by analyzing these packet-level characteristics. This eBPF program attempts to normalize these values to make passive fingerprinting harder.

## How does it work?

eBPF programs run in the kernel with strict safety guarantees enforced by the verifier. This program:

1. Attaches to a network interface's TC egress hook
2. Inspects every outgoing packet
3. Modifies packet headers in-place (TTL, TCP options, etc.)
4. Recalculates checksums where necessary
5. Passes the modified packet onwards

The verifier ensures the program can't crash the kernel, access arbitrary memory, or run forever. All bounds checks are verified at load time.

## Limitations

- **Linux only** - eBPF is a Linux kernel feature
- **Requires kernel 4.15+** - uses `bpf_skb_change_tail` for packet modifications
- **Root/CAP_NET_ADMIN required** - kernel hooks need elevated privileges
- **Egress only** - only modifies outgoing packets (ingress fingerprinting still works)
- **Not comprehensive** - doesn't cover all fingerprinting vectors (e.g., TCP options ordering, TCP timestamps beyond randomization, ICMP behavior)

## Verify

Verify it's running:

```bash
$ sudo tc filter show dev <interface> egress
```

Verify w/ tcpdump output, some examples below:

```bash
$ tcpdump -i <interface> -vvv -Q out
$
$ # View specific TCP/IP fields:
$ tcpdump -i <interface> -vvv -c 20 -Q out 'tcp[tcpflags] & tcp-syn != 0'  # SYN packets only (-c for 20 packets)
$ tcpdump -i <interface> -vvv -nn -Q out | grep -E 'ttl|win|mss|wscale'  # Filter for specific fields
$
$ # More detailed packet inspection:
$ tcpdump -i <interface> -vvv -XX -Q out  # Show full hex dump
$ tcpdump -i <interface> -vvv -Q out port 443  # HTTPS traffic only
```

## Configuration

Edit `ttl_editor.c` and modify the `#define` values at the top:

```c
#define FORCE_TTL 255
#define SPOOF_TCP_WINDOW_SIZE 65535
#define SPOOF_TCP_MSS 1460
#define SPOOF_TCP_WINDOW_SCALE 5
// etc.
```

Then recompile with `make`.

## References

- eBPF: https://ebpf.io/
- TC (Traffic Control): https://man7.org/linux/man-pages/man8/tc.8.html
- p0f (passive OS fingerprinting): https://lcamtuf.coredump.cx/p0f3/
- nmap OS detection: https://nmap.org/book/osdetect.html
