# 404 v1.0
Rust privacy proxy & Linux kernel module. Full client-fingerprint control.

[Quick Start](#quick-consent--warning)

[Join the Discord for support!](https://discord.gg/G7rUYrZqS2)

**Main Discussion:** GitHub discussions

*Alternative community options coming soon!*

## Quick consent & warning

*By running this software you understand that:*
- This proxy will generate a local CA and key-pair on its first run. As of now, there is no functionality or instructions for adding or removing these to your trust store.
- **This proxy terminates TLS** usernames and passwords that pass through this proxy may be stored/visible in ***local only*** logs. Do not share logs. 
- This is beta software - no warranty, no guarantees, minimal support.

*...and agree that:*
- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- If you find a security issue report it to 404mesh@proton.me

## What is 404?

404 houses two main modules:
- STATIC Proxy - *Synthetic Traffic and TLS Identity Camouflage*
- Linux eBPF module

### STATIC Proxy

The heart of 404, built in Rust. 

> Native values from FingerprintJS [here](.github/IMAGES/cleanFire).

> Spoofed values from FingerprintJS [here](.github/IMAGES/dirtyFire).

I want to start by saying I started learning Rust on November 17. As of writing this, that is eight days ago. If you see something I did wrong or could do better, open an issue. 

That being said, the STATIC proxy is built from the ground up and wired specifically to give the user granular control over their fingerprint. Not just their browser fingerprint, but any device or app they choose to route through the proxy.

As it stands in v1.0, STATIC runs on localhost:8080 by default, never exposing itself to the internet or any device other than the one that it is running on. The logic behind STATIC is pretty simple and mimics a lot of the high-level logic that `mitmproxy` employs. 

Requests are broken into `flow`s. Each `flow` passes through multiple `stage`s. A stage is where the request/response mutation happens. 

Request stages:
1.  

Response stages:
1. 

I am getting consistently spoofed values from the following fingerprinting websites: 
1. https://demo.fingerprint.com/playground
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/
5. https://httpbin.org/headers

If you go through the JS files under static_proxy/assets/*.js, you will find extensive coverage of many fingerprinting vectors. This includes, but is not limited to:

1. Navigator property proxy
2. WebRTC protection - you can still use your peripherals, they just don't leak as much data. Local IP remains private when allowing browser access to peripherals. Peripheral names (device id, model #) are also spoofed.
3. Canvas pollution
4. Iframe propagation
5. Plugin spoofing
6. Font protection (multi-layered)

### Linux eBPF module

The eBPF module is, again, quite simple. It leverages powerful, fast, well documented, low-level Linux kernel hooks. By attaching carefully crafted eBPF programs to Linux's Traffic Control (tc) egress hooks, we can mutate files extensively.

Currently, the following is implemented:
```md
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
```

## How do I install and run this on my machine?

### Requirements

- `rust`  - [INSTALL](https://rust-lang.org/tools/install/)
- `NASM`  - [INSTALL](https://www.nasm.us/pub/nasm/releasebuilds/3.01/)
- `Cmake` - [INSTALL](https://cmake.org/download/)

> Utilizing the eBPF module requires a Linux kernel (4.15+).

### 1. Edit environment variables (WINDOWS)

1. Find donwload locations of `NASM` and `Cmake`
    
    Defaults should be...
    - `C:\Program Files\NASM
    - `C:\Program Files\Cmake\bin

2. Search for "edit environment" in the Windows search and open the control pane
3. In the top pane under `User variables for USER` click on `Path` then `Edit...` a new window will open
4. Click on `New` at the top right corner of the new window and paste the path to `NASM` and `cmake\bin`

> Rust downloads itself to your `.cargo/bin` automatically.

### 2. Run the proxy

```bash
$ cargo run   # This will take a while on the first run.
```

### 3. Trust proxy-generated CA

1. Navigate to the 404/ directory and locate the ../static_proxy/certs/ directory.
2. Click on the file labeled `static-ca.crt` (may not have .crt)
3. Follow the instructions to install to `Trusted Root Certificate Authorities`

*Configure your browser (or machine) to use localhost:8080 (127.0.0.1:8080) as an HTTP/S proxy.*

***Important:*** **This tool is a TLS-terminating proxy (man-in-the-middle) and has access to your plaintext HTTPS data (usernames, passwords, certain message protocols, etc.). Do NOT share your CA cert with *anyone* for *anything, ever*.**

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

You *100% could* configure a VM and route traffic from your host machine to a VM guest, [instructions for VM configuration here (not yet, sorry)](docs/VMConfig.md).

For now, just running STATIC should be enough, though network level obfuscation will not be possible without a Linux kernel.

## Why should I install and run this on my machine?

The core of the traffic obfuscation is solid and functional. When properly configured, this software defeats modern fingerprinting techniques. Seriously. However, the included `profiles.json` is still being refined. The profiles work, but require manual review and adjustment to ensure coherence for your specific use case. 

If you’re comfortable with **technical setup**, **manual maintenance**, and **iteration**, you’ll get real privacy gains. If you need plug-and-play, check back in a few weeks.

## Why *shouldn't* I install and run this on my machine?

If you do not understand JavaScript, or if you don't take the time to look through the code, there is almost no point in you downloading this proxy. The point of this is not to be a privacy proxy. **Not yet.** This repository, in its current state, is experimental and intended only for educational, research, and development purposes. 

### Things will break

Routing your traffic through this proxy means your browser *will* be brittle. As mentioned earlier, Firefox is much more forgiving.

Your web page will look... strange. Most sites *will* be readable, but if the server thinks it's talking to Firefox, your Chrome page will not load 100% properly. Breakage is much less frequent in Firefox. Experimenting witn the JavaScript for canvas/webGL may improve functionality.

I do not know the long term effects on account usage. I have been logging-in via this proxy using my personal Google, Microsoft, and Apple accounts for the last 6-ish months, and I have experienced no retaliation (bans and whatnot). That is *not* to say you will have the same experience. **I *strongly* recommend that you use alternate/disposable accounts if you're going to be testing OAuth or other login flows.**

I am not a cybersecurity engineer. I hammered this together and may have missed something important. Feel free to reach out with security vulnerabilities @ 404mesh@proton.me

## The dream
