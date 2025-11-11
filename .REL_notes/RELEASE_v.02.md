# 404 v.02 Release Notes

## What Changed

v.01 handled browser-level fingerprinting. v.02 adds network packet-level fingerprinting via eBPF.

## New: eBPF Packet Manipulation

**What it does:**
- Modifies outgoing TCP/IP packets before they leave your machine
- Rewrites TTL, TCP window size, initial sequence numbers, MSS, window scale
- Runs in kernel space via Linux TC (Traffic Control) egress hooks
- Handles IPv4 and IPv6 TCP/UDP traffic

**Why it matters:**
Tools like nmap and p0f can fingerprint your OS by analyzing packet headers. Windows uses TTL=128, Linux/macOS use TTL=64. TCP window sizes, MSS values, and TCP option ordering are all OS-specific. Even if your browser pretends to be Chrome on Windows, your network stack screams "I'm actually Linux."

> In its current state, 404's eBPF layer only further distinguishes you from the crowd. You may further tinker with values to attempt to blend in, but our research in the variability of these fingerprints and how to mutate them in a safe and meaningful way is not done. If you would like to join the research, reach out - 404mesh@proton.me

Tools that allow for browser automation (selenium, puppeteer, curl, etc.), have a very unique fingerprint. The eBPF layer and the proxy layer will work together to ensure that all traffic leaving your machine is homogenized. While automated flows have not yet been implemented, the main hurdles I am having are legal ones. Automation oftentimes breaks ToS on strict websites. That being said, these two layers working in tandem will allow automation and data poisoning to be implemented seamlessly.

Browser fingerprinting is well-studied. Packet-level fingerprinting is less discussed but equally trivial to collect. Network observers (ISPs, CDNs, state actors) can passively log your OS, browser, and network stack implementation without ever touching your cookies or localStorage.

> The eBPF program in this release normalizes packet headers to combat passive OS fingerprinting.

## Limitations

### eBPF Gaps

This is proof-of-concept. It handles common fingerprinting vectors but misses:
- **TCP option ordering** - Windows, Linux, and macOS order TCP options (MSS, SACK, timestamps, window scale) differently. eBPF verifier makes dynamic TCP option reordering difficult.
- **ICMP behavior** - OS-specific ICMP reply patterns not handled.
- **Ingress fingerprinting** - Only modifies outgoing packets. Observers can still analyze server responses and infer client OS.
- **Profile synchronization** - Doesn't read from `profiles.json` yet. Uses hardcoded defaults.

nmap has ~70 OS fingerprinting methods. This covers maybe 30-40% of them.

## Roadmap

### Soon
- Sync eBPF with `profiles.json` (pass profile values to kernel - mark @ mitmproxy)
- VM images
- TCP option ordering mutation
- ICMP fingerprinting protection
- Ingress packet mutation

### Later
- Behavioral noise layer (automated profile simulation)
- Cookie/SSO token handling
- Plausible contradictory traffic generation

### Long-term
- Windows/macOS support via packet filter drivers (if feasible)
- Distributed coordination (multiple profiles, session rotation)
- Network-level timing obfuscation
- Full nmap evasion (asymptotic goal, likely impossible)

## License

AGPL-3.0
