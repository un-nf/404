## Configure a Linux VM for forwarding

**Kernel requirements:**

- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_NET_CLS_BPF=y, CONFIG_NET_ACT_BPF=y
- Install: `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`, `iproute2`

- Linux kernel 4.15+ (5.4+ recommended)
- Two network adapters:
  1. `Bridged` - connects `VM/Guest` to internet
  2. `Host-Only` - creates private network between `Host` and `VM/Guest`

### 4a. Compile & attach eBPF program to TC egress hook (if using Linux)

**Build eBPF program**
> Currently, IP/TCP packet header values are assigned via global variables at the top of `src/ebpf/ttl_editor.c`.

*Modify these to desired values *before* compiling.*

```bash
$ $ cd src/ebpf
$ make deps-install  # shows dependency installation command
$ make               # compiles ttl_editor.o
$ 
$ # Manual compilation
$ clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/ -I/usr/include/linux -c TTLEDIT-STABLE.c -o <output>.o

```

**Attach to network interface:**

```bash
$ sudo tc qdisc add dev <interface> clsact
$ sudo tc filter add dev <interface> egress bpf da obj ttl_editor.o sec classifier

```
**Route host traffic through VM:**

On `Linux VM` (Guest):
```bash
# Enable IP forwarding
$ sudo sysctl -w net.ipv4.ip_forward=1
$ echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
$ sudo sysctl -w net.ipv6.conf.all.forwarding=1
$ echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf

# Allow forwarding on Host-Only interface
$ sudo iptables -A FORWARD -i <host-only-interface> -j ACCEPT
$ sudo iptables -A FORWARD -o <host-only-interface> -j ACCEPT
$ sudo ip6tables -A FORWARD -i <host-only-interface> -j ACCEPT
$ sudo ip6tables -A FORWARD -o <host-only-interface> -j ACCEPT

# Enable NAT/masquerading on Bridged interface
$ sudo iptables -t nat -A POSTROUTING -o <bridged-interface> -j MASQUERADE
$ sudo ip6tables -t nat -A POSTROUTING -o <bridged-interface> -j MASQUERADE

```

On Host machine:
- Set default gateway to `VM/Guest` Host-Only adapter IP address
- (Windows: Network adapter settings → Properties → TCP/IPv4 → Gateway)
- (Linux/Mac: `sudo route add default gw <vm-host-only-ip>`)

> Some additional tinkering may be required. Feel free to leave a comment or open an issue with suggestions on improving the setup process. *If you have any experience developing with the Linux kernel, I am interested in building a minimal kernel with only the key elements, but beyond my scope (for the time being) and would love some assistance or guidance.*
