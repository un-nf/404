# 404 v1.0
Rust privacy proxy & Linux kernel module. Full client-fingerprint control.

> **404 is a dual-module network application designed to give uers profile-driven control over multiple layers of their fingerprint: TCP/IP options (TTL, MSS, etc.), TLS cipher-suite, HTTP headers, browser APIs, canvas, WebRTC, and more...**

---

**ToC:**
- [What is 404?](#what-is-404)
- [Quick Start](#how-do-i-install-and-run-this-on-my-machine)
- [Why does this matter?](#why-should-i-install-and-run-this-on-my-machine)

---

## Quick consent & warning

*By running this software you understand that:*
- This proxy will generate a local CA and key-pair on its first run. As of now, there is no functionality or instructions for removing these from your trust store.
- **This proxy terminates TLS**, usernames and passwords that pass through this proxy may be temporarilt stored/visible in ***local only*** logs. Do not share logs. 
- This is beta software - no warranty, no guarantees, minimal support.

*...and agree that:*
- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- If you find a security issue report it to 404mesh@proton.me

[Join the Discord for support!](https://discord.gg/G7rUYrZqS2)

**Main Discussion:** GitHub discussions

*Alternative community options coming soon!*

---

## What is 404?

404 houses two main modules:
- STATIC Proxy - *Synthetic Traffic and TLS Identity Camouflage*
- Linux eBPF module

### STATIC Proxy
#### *Synthetic Traffic and TLS Identity Camouflage*

The heart of 404, built in Rust. 

> Native values from FingerprintJS ![here](.github/IMAGES/cleanChrome.png).

> Spoofed values from FingerprintJS ![here](.github/IMAGES/dirtyChrome.png).

*I want to start by saying I am new to the Rust ecosystem, If you see something I did wrong or could do better, open an issue.*

That being said, the STATIC proxy is built from the ground up and wired specifically to give the user granular control over their fingerprint. Not just their browser fingerprint, but any device or app they choose to route through the proxy.

As it stands in v1.0, STATIC runs on localhost:8080 by default, never exposing itself to the internet or any device other than the one that it is running on. The logic behind STATIC is pretty simple and mimics a lot of the high-level logic that `mitmproxy` employs. 

Requests are broken into `flow`s. Each `flow` passes through multiple `stage`s. A stage is where the request/response mutation happens. 

**Request stages:**
1. **HeaderProfileStage** - Rewrites headers based on your selected profile (User-Agent, Accept, sec-ch-ua, Accept-Language). Maintains strict ordering to match real browser behavior: remove -> replace -> replaceArbitrary -> replaceDynamic -> set -> append.
2. **AltSvcStage** - Downgrades or strips HTTP/3 advertisements to prevent protocol leakage.
3. **CspStage** - Generates CSP nonces and rewrites Content-Security-Policy headers so injected scripts execute without breaking origin policies.
4. **JsInjectionStage** - Embeds the fingerprint spoofing stack (bootstrap, globals shim, config layer, spoof scripts) near `</head>` or `</body>`. Records SHA-256 hashes for CSP validation.
5. **BehavioralNoiseStage** - Tags the flow with timing patterns for coordination between Rust and injected JavaScript.

**Response stages:**
1. **CspStage (response)** - Finalizes CSP headers with script hashes and nonces, handles strict-dynamic policies, preserves origin inline scripts.
2. **JsInjectionStage (response)** - Performs the actual HTML mutation, decompresses responses if needed (gzip/deflate/brotli), injects scripts at the earliest safe insertion point.
3. **AltSvcStage (response)** - Strips or normalizes Alt-Svc headers in responses to prevent the browser from upgrading to HTTP/3.

Each stage runs asynchronously and can inspect or mutate the request/response. The pipeline is deterministic. Same profile, same mutations, same fingerprint.

Don't believe me? Check my work... 
1. https://demo.fingerprint.com/playground
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/
5. https://httpbin.org/headers

### Linux eBPF module

The eBPF module is, again, quite simple. It leverages powerful, fast, well documented, low-level Linux kernel hooks. By attaching carefully crafted eBPF programs to Linux's Traffic Control (tc) egress hooks, we can mutate files extensively.

Currently, the following is implemented:
```md
**IPv4:**
- TTL (Time To Live) -> forced to 255
- TOS (Type of Service) -> set to 0x10
- IP ID (Identification) -> randomized per packet
- TCP window size -> 65535
- TCP initial sequence number -> randomized (again)
- TCP window scale -> 5
- TCP MSS (Maximum Segment Size) -> 1460
- TCP timestamps -> randomized

**IPv6:**
- Hop limit -> forced to 255
- Flow label -> randomized
```

---

## How do I install and run 404 on my machine?

### Requirements

> Utilizing the eBPF module requires a Linux kernel (4.15+).

| Component | Version | Install Link |
|-----------|---------|-------|
| **Rust** | 1.76+ | [INSTALL](https://rust-lang.org/tools/install/) - *manual install req.* |
| **CMake** | Latest | [INSTALL](https://www.nasm.us/pub/nasm/releasebuilds/3.01/) |
| **NASM** | Latest | [INSTALL](https://cmake.org/download/) |

Default install locations...
    - `C:\Program Files\NASM`
    - `C:\Program Files\CMake\bin`

### 1. Install dependencies & configure PATH

<details>
<summary><b>Windows</b></summary>

**Option 1: Install via winget (recommended)**

```powershell
# Install CMake
$ winget install Kitware.CMake

# Install NASM (interactive - choose installation directory when prompted)
$ winget install nasm -i
```

*Restart your shell after installation. Tools should be on your PATH automatically.*

**Option 2: Manual installation**

Add to PATH:

   - Search for "*edit environment*" in Windows search and open the control panel
   - Under `User variables for %USER%` click on `Path` then `Edit...`
   - Click `New` and add the paths to `NASM` and `CMake\bin`

Default install locations...
    - `C:\Program Files\NASM`
    - `C:\Program Files\CMake\bin`

</details>

<details>
<summary><b>macOS</b></summary>

**Install via `Homebrew`**

```bash
# Install Homebrew if you don't have it
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
$ brew install rust nasm cmake

# Rust, NASM, and CMake should be on your PATH automatically
```

</details>

<details>
<summary><b>Linux</b></summary>

**Install via package manager**

```bash
# Debian/Ubuntu
$ sudo apt update
$ sudo apt install -y curl build-essential nasm cmake

# Arch
$ sudo pacman -S rust nasm cmake

# Fedora/RHEL
$ sudo dnf install -y rust cargo nasm cmake

# Install Rust via rustup (if not installed via package manager)
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
```

</details>

### 2. Run the proxy

```bash
$ cargo run   # This will take a while on the first run.
```

### 3. Trust proxy-generated CA

<details>
<summary><b>Windows</b></summary>

1. Navigate to the `404/` directory and locate the `../static_proxy/certs/` directory.

2. Double-click the file labeled `static-ca.crt` (may appear without .crt extension)

3. Click `Install Certificate...`

4. Select `Current User` and click `Next`

5. Choose `Place all certificates in the following store` and click `Browse...`

6. Select `Trusted Root Certification Authorities` and click `OK`

7. Click `Next` then `Finish`

</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Open Keychain Access and import the CA
$ sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain static_proxy/certs/static-ca.crt

# Or use the GUI:
# 1. Open Keychain Access
# 2. File -> Import Items -> select static-ca.crt
# 3. Find the certificate, double-click it
# 4. Expand "Trust" and set "When using this certificate" to "Always Trust"
```

</details>

<details>
<summary><b>Linux</b></summary>

```bash
# Copy CA to system trust store
$ sudo cp static_proxy/certs/static-ca.crt /usr/local/share/ca-certificates/static-ca.crt
$ sudo update-ca-certificates

# For Firefox specifically (uses its own trust store):
# Open Firefox -> Settings -> Privacy & Security -> Certificates -> View Certificates
# -> Authorities tab -> Import -> select static-ca.crt
# -> Check "Trust this CA to identify websites" -> OK
```

</details>

**Configure your browser:**

Set your browser (or system) to use `localhost:8080` (or `127.0.0.1:8080`) as an HTTP/HTTPS proxy.

- **Chrome/Edge:** Settings -> System -> Open your computer's proxy settings
- **Firefox:** Settings -> Network Settings -> Manual proxy configuration -> HTTP Proxy: `127.0.0.1`, Port: `8080`, check "Also use this proxy for HTTPS"

***Important:*** **This tool is a TLS-terminating proxy (man-in-the-middle) and has access to your plaintext HTTPS data (usernames, passwords, certain message protocols, etc.). Do NOT share your CA cert with *anyone* for *anything, ever*.**

*UX on Firefox is slightly more stable for reasons that are not clear to me. Would love some insight. Login flows have been tested and are working in both browsers.*

### 4a. Compile & attach eBPF program to TC egress hook (if using Linux)

*The eBPF `ttl_editor` modifies packet-level fingerprints (TTL, TCP window size, sequence numbers, etc.). This requires a Linux kernel.*

![tcpdump output](.github/IMAGES/tcpdump_output.png)

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

For now, just running STATIC should be enough, though network level obfuscation is not possible without a Linux kernel (yet).

---

## Why should I install and run this on my machine?

Your online fingerprint is becoming increasingly unique. Modern tracking doesn't just rely on cookies; it builds "personality clouds" from hundreds of data points: TLS handshake patterns (JA3/JA4), HTTP header combinations, canvas rendering quirks, microphone/speaker/headset model and brand, font enumeration, WebGL parameters, audio context characteristics, and behavioral timing patterns... to name a few.

The collection of these semi-unique values (.nav properties, timezone, screen resolution, browser type, etc.) allows servers to pretty confidently identify users as not semi-unique, but entirely. 

Commercial fingerprinting services like FingerprintJS, Fingerprint.com, and DataDome can identify users across...
- Different browsers on the same device
- Private/incognito modes (linked to 'public' browsing profile)
- VPN connections (or proxies, even residential ones)
- Cookie & cache clearing 
- Different networks

This isn't paranoia. This is surveillance capitalism.

### What 404 actually does...

404 doesn't aim to hide you or anonymize your traffic, that's what Tor is for. Instead, 404 corrupts your data by creating coherent false signals across multiple layers...

**Network Layer (3/4)** - *eBPF*
- Spoofs TCP/IP fingerprints (TTL, window size/scale, MSS, seq. numbers)
- Randomizes IP identification fields
- Normalizes TCP timestamps

**Protocol Layer (6)** - *STATIC Proxy*
- Spoofs TLS handshakes (cipher-suite control)
- Supports HTTP/1.1 and HTTP/2
- Downgrades Alt-Svc headers to prevent HTTP/3 leakage

**Application Layer (7)** - *STATIC Proxy* & *JavaScript Behavioral Engine*

*HTTPS Headers...*
- Profile driven header normalization (User-Agent, Accept, Accept-Language, sec-ch-ua-*)
- Removes tracking headers (X-Client-Data, etc.)
- Maintains header ordering consistency per profile

*JavaScript...*
- Navigator property spoofing (platform, userAgent, hardwareConcurrency, etc.)
- Canvas fingerprint pollution
- WebGL parameter normalization
- WebRTC protection (local IP masking, device ID spoofing)
- Font enumeration blocking (multi-layered defense)
- Geolocation + automation evasion
- Iframe context propagation

> These layers reinforce each other. If you only spoof JavaScript, packet analysis reveals you. If you only spoof TLS, browser APIs reveal you. 404 creates coherent false fingerprints where every layer tells the same lie.

### Who is this for?

Anyone who's tired of being tracked across the web despite "privacy tools" that don't actually work against modern fingerprinting.

404 has the capability to defeat modern fingerprinting techniques. 

The included profiles (`firefox-windows`, `chrome-windows`, `edge-windows`) produce consistent spoofed fingerprints but are still under active development. Setup is straightforward if you're comfortable with:

If you’re comfortable with **manual maintenance** and **iteration**, you’ll get real privacy gains.

### The Bigger Picture

This isn't just a tool. It's proof that illegibility is technically feasible.

As governments worldwide push for mandatory surveillance (Chat Control in the EU, client-side scanning proposals, "lawful access" backdoors), and as AI makes behavioral profiling trivial at scale, the ability to be untrackable becomes existential.

404 demonstrates that privacy through illegibility isn't theoretical. It's implementable, it works, and it's available to anyone.

---

## Why *shouldn't* I install and run this on my machine?

If you do not understand JavaScript, or if you don't take the time to look through the code, there is almost no point in you downloading this proxy. The point of this is not to be a privacy proxy. **Not yet.** This repository, in its current state, is built for researchers, developers, and privacy advocates who understand the trade-offs and are comfortable with...

***Manual configuration*** - Profiles require review and occasional tweaking based on your use-case and threat model. If you're confused about configuration, feel free to reach out in an [email](mailto:404mesh@proton.me), open a [GitHub issue](https://github.com/un-nf/404/issues), or [submit a ticket](https://discord.gg/G7rUYrZqS2) in the Discord.

***!Occasional! breakage*** - Breakage is honestly limited to having to manually solve a captcha every now and again. Still, some websites will break, some login flows will fail, some features won't work. This is the nature of deep protocol mutation. If there's something critical, open a [GitHub issue](https://github.com/un-nf/404/issues) and I will try to find a workaround.

***Active maintenance*** - Browser updates change fingerprinting surfaces. Profiles need updating. You can't just "set it and forget it." I will update as frequently as I can.

***Technical comlexity*** - It's a lot. I know, but honestly it kind of just works right now. It may get you rate-limited or flagged as a bot (I haven't been yet, and I run this jawn every day), but you should be able to pass Captchas and prove you're a human -- no, the pole is not a part of the 'street light.'

> I do not know the long term effects on account usage. I have been logging-in via this proxy using my personal Google, Microsoft, and Apple accounts for the last 6-ish months, and I have experienced no retaliation (bans and whatnot). That is *not* to say you will have the same experience. **I *strongly* recommend that you use alternate/disposable accounts if you're going to be testing OAuth or other login flows.**

*I am not a cybersecurity engineer. I hammered this together and may have missed something important. Feel free to reach out with security vulnerabilities @ 404mesh@proton.me*

---

## The dream