# 404 v.03
Multi-layer client fingerprinting resistance software.

> NEW (.02): eBPF support for TCP/IP packet header modification.

> NEW (.03): JavaScript proxies!

> NEW (.03): WebRTC and font protection. *Deterministic fingerprint*

[Join the Discord for support!](https://discord.gg/G7rUYrZqS2)
**Main Discussion:** GitHub discussions

*Alternative community options coming soon!*

## Quick consent & warning
By running this software you accept and understand that:
- The proxy decrypts HTTPS for rewriting/testing. It can see ***passwords*** and ***session tokens***.
- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- This is research software - no warranty, no guarantees, minimal support.
- If you find a security issue report it to 404mesh@proton.me

## Why should I install and run this on my machine?

The core of the traffic obfuscation is solid and functional. When properly configured, this software defeats modern fingerprinting techniques. Seriously.

However, the included `profiles.json` is still being refined. The profiles work, but require manual review and adjustment to ensure coherence for your specific use case.

If you’re comfortable with technical setup, manual maintenance, and iteration, you’ll get real privacy gains. If you need plug-and-play, check back in a few weeks.

### Kernel level packet spoofing

> As of v.02, this project also provides tooling to modify outgoing network packet headers by attaching to the traffic control (tc) egress hook. Currently, the following is implemented:

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

### Comprehensive JS coverage

If you go through the JS files starting with 0/1/2, you will find extensive coverage of many fingerprinting vectors. This includes, but is not limited to:

1. Font protection (multi-layered)
2. WebRTC protection - you can still use your peripherals, they just don't leak as much data. Local IP remains private when allowing browser access to peripherals.
3. Canvas pollution
4. Iframe propagation
5. Plugin spoofing
6. Viewport rounding
7. Navigator property proxy

### Consistent fingerprints

This proxy allows you to experiment with browser-visible fingerprint mutation. Client identification is getting scary precise and the public does not have the tools to remain private with implementations of policies like Chat Control. 

A small win, I am getting consistently spoofed values from the following fingerprinting websites: 
1. https://demo.fingerprint.com/playground
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/
5. https://httpbin.org/headers

>values from FingerprintJS (fingerprint.com) [here](.github/IMAGES/).

## How do I install and run this on my machine?

As of now, the only requirement is `mitmproxy` (and thus, a compatible `Python` version).

Utilizing the eBPF module requires a Linux kernel (4.15+). 

### 1. Install venv

venv installation (WINDOWS):

In 404 directory:

```cmd
> python -m venv <venv_name>
> .\venv\Scripts\activate
> pip install mitmproxy

```

venv installation (MacOS):

In 404 directory:

```bash
$ python3 -m venv <venv_name>
$ source <venv_name>/bin/activate
$ pip install mitmproxy

```

setup (Linux)

In 404 directory:
```bash
$ sudo apt install python mitmproxy
```

*Configure your browser (or machine) to use localhost:8080 (127.0.0.1:8080) as an HTTP/S proxy.*

***Important:*** **This tool is a TLS-terminating proxy (man-in-the-middle) and has access to your plaintext HTTPS data (usernames, passwords, certain message protocols, etc.). Do NOT share your CA cert with *anyone* for *anything, ever*.**

### 2. Install mitmproxy CA cert

On CLIENT (Windows Command Prompt/MacOS Terminal):
Choose mitmproxy method:
- `mitmproxy` # interactive CLI
- `mitmdump`  # headless
- `mitmweb`   # web UI

1. 
```bash
$ mitmproxy
```
2. In browser, navigate to https://mitm.it - **Follow instructions** to install CA cert

### 3. Run mitmproxy w/ addon

1. Close original mitmproxy instance and run:

```bash
$ mitmproxy -s src\proxy\header_profile.py <args>

# All mitmproxy CLI rules apply.
# Works with no further arguments.
# Documentation @ https://docs.mitmproxy.org/stable/

```

*UX on Firefox is much more stable for reasons that are not clear to me. Would love some insight. Google login works on Firefox.*

### 4a. Compile & attach eBPF program to TC egress hook (if using Linux)

*The eBPF `ttl_editor` modifies packet-level fingerprints (TTL, TCP window size, sequence numbers, etc.). This requires a Linux kernel.*

![tcpdump output](https://raw.githubusercontent.com/un-nf/404/refs/heads/main/.github/IMAGES/tcpdump_output.png "tcpdump output")

**Kernel requirements:**

- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_NET_CLS_BPF=y, CONFIG_NET_ACT_BPF=y
- Install: `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`, `iproute2`

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

### 4b. Configure a Linux VM (if not using Linux)

**VM Setup:**

> *VM images coming soon. I am using VMWare to host a Deb-Bookworm distribution. Works mildly well, but really heavy. Definitely going to be looking into distributing the VMs as dedicated server images, not gerry-rigged forwarding machines with desktop environments.*

You *100% could* configure a VM and route traffic from your host machine to a VM guest, instructions for this will be at the bottom of this document.

For now, just running mitmproxy should be enough, though network level obfuscation will not be possible without a Linux kernel.

## Why *shouldn't* I install and run this on my machine?

If you do not understand JavaScript, or if you don't take the time to look through the code, there is almost no point in you downloading this proxy. The point of this is not to be a privacy proxy. **Not yet.** This repository, in its current state, is experimental and intended only for educational, research, and development purposes. 

### Things will break

Routing your traffic through this proxy means your browser *will* be brittle. As mentioned earlier, Firefox is much more forgiving.

Your web page will look... strange. Most sites *will* be readable, but if the server thinks it's talking to Firefox, your Chrome page will not load 100% properly. Breakage is much less frequent in Firefox. Experimenting witn the JavaScript for canvas/webGL may improve functionality.

I do not know the long term effects on account usage. I have been logging-in via this proxy using my personal Google, Microsoft, and Apple accounts for the last 6-ish months, and I have experienced no retaliation (bans and whatnot). That is *not* to say you will have the same experience. **I *strongly* recommend that you use alternate/disposable accounts if you're going to be testing OAuth or other login flows.**

I am not a cybersecurity engineer. I hammered this together and may have missed something important. Feel free to reach out with security vulnerabilities @ 404mesh@proton.me

## The dream
