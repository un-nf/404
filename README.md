# 404 v1.0
*404 acts as the middleman between you and those collecting your data.*
Rust privacy proxy & Linux kernel module. Full client-fingerprint control. 

> **404 is a dual-module network application designed to give uers profile-driven control over multiple layers of their fingerprint: TCP/IP options (TTL, MSS, etc.), TLS cipher-suite, HTTP headers, browser APIs, canvas, WebRTC, and more...**

---

**ToC:**
- [***View the manual instead***](https://un-nf.github.io/404-docs/)
- [What is 404?](https://un-nf.github.io/404-docs/Overview/whatIs/)
- [Quick Start](https://un-nf.github.io/404-docs/dev/downloadDev/)
- [Why does this matter?](https://un-nf.github.io/404-docs/Overview/why404/)

---

https://github.com/user-attachments/assets/fb403522-ac09-4c49-a599-5edd53f33994

---

## Quick consent & warning

*By running this software you understand that:*
- This proxy will generate a local CA and key-pair on its first run. As of now, there is no functionality or instructions for removing these from your trust store.
- **This proxy terminates TLS**, usernames and passwords that pass through this proxy may be temporarily stored/visible in ***local only*** logs. Do not share logs. 
- This is beta software - no warranty, no guarantees, minimal support.

*...and agree that:*
- You will not use your primary accounts.
- You will not share your CA certificate with anyone.
- If you find a security issue report it to 404co@proton.me

[Join the Discord for support!](https://discord.gg/X9QrVm6dqS)

**Main Discussion:** GitHub discussions

*Alternative community options coming soon!*

---

## What is 404?

404 houses two main modules:
- STATIC Proxy - *Synthetic Traffic and TLS Identity Camouflage*
- Linux eBPF module

### STATIC Proxy
#### *Synthetic Traffic and TLS Identity Camouflage*

The STATIC proxy is built from the ground up and wired specifically to give the user granular control over their online fingerprint. Not just their browser fingerprint, but any device or app they choose to route through the proxy.

Don't believe me? Check my work... 
1. https://demo.fingerprint.com/playground
2. https://browserleaks.com/
3. https://coveryourtracks.eff.org/
4. https://whatismybrowser.com/
5. https://httpbin.org/headers

### Linux eBPF module

The eBPF module is, again, quite simple. It leverages powerful, fast, well documented, low-level Linux kernel hooks. By attaching eBPF programs to Linux's `Traffic Control` (`tc`) egress hooks, we can mutate packets extensively.

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

### 1. Install dependencies & configure PATH

> **Developer Tip:** All commands can be copy pasted into your terminal for easy usage!

<details>
<summary><b>Windows</b></summary>

**Install via winget**

1. Click [here](https://static.rust-lang.org/rustup/dist/i686-pc-windows-msvc/rustup-init.exe) (32-bit) to download rust-up. Open the downloaded `.exe` file and follow setup instructions.

   - Use the "Workload" tab to select the "Desktop Development with C++" option.
   - [Help](https://rust-lang.github.io/rustup/installation/windows-msvc.html)

2. Open the Command Prompt

   - Press Windows + R
   - Type "cmd" into the run dialogue box.

3. Download the dependencies

```bash
winget install --id Kitware.CMake -e && winget install --id NASM.NASM -e

```

*Restart your shell after installation. Tools should be on your PATH automatically.*

</details>

<details>
<summary><b>macOS</b></summary>

**Install via homebrew (recommended)**

1. Open the Terminal

   - Press Command + Space
   - Search "Terminal" and press Enter

2. Ensure you have homebrew installed

a.
```zsh
xcode-select --install

```

b.
```zsh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

```

3. Download dependencies w/ homebrew:

```zsh
brew install rust nasm cmake

```

*Restart your shell after installation. Tools should be on your PATH automatically.*

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

> **Info:** All steps assume that there is a folder named `404/` located at `~/git/`

**Linux/macOS:**

```bash
cd ~/git/404/src/STATIC_proxy # CHANGE to wherever you unzipped the 404 folder.
cargo run  # This will take a while on the first run (~5-minutes)

```

**Windows:**

```bash
cd %USERPROFILE%\git\404\src\STATIC_proxy # CHANGE to wherever you unzipped the 404 folder.
cargo run  # This will take a while on the first run (~5-minutes)

```

### 3. Trust proxy-generated CA

<details>
<summary><b>Firefox</b></summary>

**Firefox uses its own trust store, you must trust the CA in the application:**

Firefox -> Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities tab -> Import -> select static-ca.crt -> Check "Trust this CA to identify websites" -> OK

</details>

<details>
<summary><b>Windows</b></summary>

**Trust the CA using `certutil`:**

```bash
certutil.exe -addstore root C:\\path\\to\\myCA.pem

```

**...or manually:**

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

```zsh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain static_proxy/certs/static-ca.crt

```

**Or use the GUI:**

1. Open Keychain Access
2. File -> Import Items -> select static-ca.crt
3. Find the certificate, double-click it
4. Expand "Trust" and set "When using this certificate" to "Always Trust"

</details>

<details>
<summary><b>Linux</b></summary>

```bash
# Copy CA to system trust store
sudo cp static_proxy/certs/static-ca.crt /usr/local/share/ca-certificates/static-ca.crt
sudo update-ca-certificates

```

</details>

### 4. Configure your Browser

Set your browser (or system) to use `localhost:8080` (or `127.0.0.1:8080`) as an HTTP/HTTPS proxy.

- **Chrome/Edge:** Settings -> System -> Open your computer's proxy settings
- **Firefox:** Settings -> Network Settings -> Manual proxy configuration -> HTTP Proxy: `127.0.0.1`, Port: `8080`, check "Also use this proxy for HTTPS"

**Important:** **This tool is a TLS-terminating proxy (man-in-the-middle) and has access to your plaintext HTTPS data (usernames, passwords, certain message protocols, etc.). Do NOT share your CA cert with *anyone* for *anything, ever*.**

*UX on Firefox is slightly more stable for reasons that are not clear to me. Would love some insight. Login flows have been tested and are working in both browsers.*

### 5. *Optional* - Configure a Linux VM (if not using Linux)

**VM Setup:**

> *VM images coming soon. I am using an Alpine distribution on WSL2 (Windows). Works well, but a little heavy. Definitely going to be looking into distributing the VMs as dedicated server images, not gerry-rigged forwarding machines with desktop environments.*

You *100% could* configure a VM and route traffic from your host machine to a VM guest, instructions for VM configuration available in the [eBPF documentation](https://un-nf.github.io/404-docs/dev/ebpf/).

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