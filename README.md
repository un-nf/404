# 404

 [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) ![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white) [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/un-nf/404)

`v2.6.0`
*404 acts as the middleman between you and those collecting your data.* [more...](https://404privacy.com)
Rust privacy proxy, WSL distro packaging path, & Linux kernel module. Full client-fingerprint control. 

> **404 is a dual-module network application designed to give users profile-driven control over multiple layers of their fingerprint: TCP/IP options (TTL, MSS, etc.), TLS cipher-suite behavior, HTTP headers, browser APIs, canvas, WebRTC, and more...**

---

**Manual Links:**
- [***View the manual instead***](https://docs.404privacy.com/)
- [What is 404?](https://docs.404privacy.com/Overview/whatIs/)
- [Quick Start](https://docs.404privacy.com/dev/)
- [Why does this matter?](https://docs.404privacy.com/Overview/why404/)

---

[![Demo](./docs/proof/demo.mp4)]

---

## Quick consent & warning

*By running this software you understand that:*

- **This proxy terminates TLS**, usernames and passwords that pass through this proxy may be temporarily stored/visible in ***local only*** logs. Do not share logs. 
- This is cutting-edge software - no warranty, no guarantees, minimal support.

*...and agree that:*

- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- If you find a security issue report it to support@404privacy.com

[Join the Discord for support!](https://discord.gg/X9QrVm6dqS)

**Main Discussion:** GitHub discussions

*Alternative community options coming soon!*

---

## What is 404?

> Got questions? [Email Me](mailto:support@404privacy.com)

404 houses two main modules:
- STATIC Proxy - *Synthetic Traffic and TLS Identity Camouflage*
- *Windows & Linux compatible* eBPF module

### STATIC Proxy
#### *Synthetic Traffic and TLS Identity Camouflage*

The STATIC proxy is built from the ground up and wired specifically to give the user granular control over their online fingerprint. Not just their browser fingerprint, but any device or app they choose to route through the proxy.

That profile contract now reaches:
- request headers and client hints
- upstream TLS hello variants and HTTP/2 behavior
- iframe propagation and worker bootstrap state
- canvas, WebGL, audio, media device, and related browser surfaces

Profile data does still drive the upstream TLS plan. STATIC passes profile-defined cipher suites, signature algorithms, curves, ALPN, and extension ordering into the `wreq` adapter, but exact wire-level parity is still bounded by what `wreq` and its TLS backend can actually emit. Unsupported claims stay in the validator as warnings, not promises of packet-perfect parity.

Best practice is to stay within your native browser family. Chromium users should choose Blink-family profiles such as Chrome or Edge. Firefox users should choose Gecko-family profiles such as Firefox. STATIC does not hard-enforce that policy for manual operators; higher-level wrappers can be stricter if they want to be.

Don't believe me? Check my work... 
1. https://demo.fingerprint.com/playground
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/
5. https://httpbin.org/headers

### Linux eBPF module

The eBPF module leverages powerful, fast, well documented, low-level Linux kernel hooks. By attaching eBPF programs to Linux's `Traffic Control` (`tc`) egress hooks, we can mutate packets extensively.

404 defaults:

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

The supported Windows path is the WSL2 distro bundle.

### Release paths

- **Windows:** use the `404-windows-x64.zip` WSL2 operator bundle
- **macOS Apple Silicon:** use `404-macos-aarch64.zip`
- **macOS Intel:** use `404-macos-x64.zip`
- **Linux:** use `static_proxy-linux-x86_64` and stage `profiles/` beside it yourself

Documentation:

- [Windows self-hosted guide](https://docs.404privacy.com/dev/windows/)
- [macOS self-hosted guide](https://docs.404privacy.com/dev/macos/)
- [Linux self-hosted guide](https://docs.404privacy.com/dev/linux/)
- [Developer build guide](https://docs.404privacy.com/dev/developers/)
- [WSL distro packaging docs](https://docs.404privacy.com/runtime/distro/)

### Windows

1. Download `404-windows-x64.zip`
2. Extract it into your Windows home folder
3. Optionally switch the default profile in `%APPDATA%\404\static\static.runtime.toml`
4. Import the distro:

The published WSL2 bundle includes:

- `404-distro.tar.gz`
- `404-distro-manifest.json`
- `404-distro-manifest.json.sig`
- Prebuilt STATIC config under `AppData\Roaming\404\static`
- Control token under `AppData\Local\404\wsl`

```powershell
wsl --import 404 "$env:LOCALAPPDATA\404\wsl\distribution" "$HOME\404-distro.tar.gz" --version 2
```

5. Start the 404 distribution:

```powershell
wsl -d 404
```

6. Query the local control plane on `127.0.0.1:4042` to fetch the generated CA and trust it on the Windows host
7. Point your browser or system proxy at `127.0.0.1:4040`

The full Windows walkthrough:

- [Windows self-hosted guide](https://docs.404privacy.com/dev/windows/)

### macOS

macOS uses the direct STATIC path.

```bash
cd "$HOME/404-runtime"
./static_proxy --config ./config/static.example.toml --list-profiles
./static_proxy --config ./config/static.example.toml --profile firefox-windows
```

The `404-runtime/` directory contains:

- `static_proxy`
- `config/static.example.toml`
- the release manifest files
- the `profiles/` catalog

If you use Chrome, switch to `chrome-windows`. If you use Edge, switch to `edge-windows`.

The bundled config listens on `127.0.0.1:4040` and exposes the local control plane on `127.0.0.1:4042`.

Full walkthrough:

- [macOS self-hosted guide](https://docs.404privacy.com/dev/macos/)

### Linux

Linux uses the direct STATIC path, the release asset is `static_proxy-linux-x86_64`.

Typical operator flow:
mkdir -p "$HOME/404-runtime"
mv "$HOME/Downloads/static_proxy-linux-x86_64" "$HOME/404-runtime/static_proxy"
chmod +x "$HOME/404-runtime/static_proxy"

git clone --depth 1 https://github.com/un-nf/404.git "$HOME/404-source"
cp -R "$HOME/404-source/src/STATIC_proxy/profiles" "$HOME/404-runtime/profiles"

cd "$HOME/404-runtime"
./static_proxy --profiles-path ./profiles --list-profiles
./static_proxy --profiles-path ./profiles --profile edge-windows
```

On the standalone Linux path, the listener defaults to `127.0.0.1:8443` and the local control plane defaults to `127.0.0.1:8445` unless you launch with a config file or explicit overrides.

Full walkthrough:

- [Linux self-hosted guide](https://docs.404privacy.com/dev/linux/)

### Build from source

If you are building locally, use the [developers guide](https://docs.404privacy.com/dev/developers/). That guide covers:

- Native macOS and Linux source builds
- Windows WSL distro build inputs
- Docker-based distro packaging
- Release artifact contract

Start here:

- [Developer build guide](https://docs.404privacy.com/dev/developers/)

### CA trust and routing

Across all paths:

- STATIC generates a local CA and you must trust it before browsers will accept proxied HTTPS
- Firefox uses its own certificate store and needs a separate import
- you only affect traffic after you point the browser or operating system at the local listener

Common listener/control-plane cases:

- macOS operator bundle: `127.0.0.1:4040` with control plane on `127.0.0.1:4042`
- Windows WSL bundle: `127.0.0.1:4040` with control plane on `127.0.0.1:4042`
- Linux standalone binary: `127.0.0.1:8443` with control plane on `127.0.0.1:8445`

**Important:** STATIC is a local TLS-terminating proxy. It can see plaintext HTTPS traffic on your machine. Do not share the generated CA certificate or private key.

### Optional Linux packet-layer path

The distro packaging path in this repo is the Windows kernel-adjacent path, and Linux still supports manual `tc` attachment when you want the packet mutator directly.

- [eBPF reference](https://docs.404privacy.com/resources/ebpf/)
- [WSL distro packaging](https://docs.404privacy.com/runtime/distro/)

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

This is surveillance capitalism.
