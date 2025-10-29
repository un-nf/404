# 404 v.01 Release Notes

## Why This Exists

The modern surveillance apparatus doesn't threaten you with death. It manages you into compliance. It sorts, categorizes, and optimizes every aspect of your digital life. Those who resist categorization are simply ignored, shadowbanned, deprioritized, rendered invisible by algorithms.

Your data isn't scattered anymore. AI agents are evaporating years of behavioral data from separate puddles and forming coherent personality clouds. The companies don't have to work hard to fingerprint you. You're handing them everything: JA3/4 TLS fingerprints, canvas hashes, WebGL signatures, font lists, hardware identification, TCP/IP stack characteristics. Passive collection. Near-zero effort. Maximum control.

VPNs hide your IP but leave your TCP/IP fingerprint untouched. Tor gets you blacklisted and interrogated. E2EE is useless when the endpoint itself is the adversary. SSO tokens follow you everywhere, linking every session, every click, every behavioral pattern into one marketable profile.

Privacy isn't just about hiding. It's about not being controlled at every step. It's about breaking the statistical models that decide what you see, what you buy, how long you stay, and who you are.

404 is an attempt to make tracking statistically worthless.

## What This Is

A local MITM proxy that mutates your digital fingerprint. No routing. No data collection. No infrastructure. Your machine does the work.

Currently implements:
- Header/fingerprint mutation with profile consistency
- JavaScript-based fingerprint spoofing (canvas, WebGL, audio, navigator properties)
- CSP-aware script injection that preserves security policies
- Multi-layer protection (preflight, config, spoofing, sandbox lockdown)
- Local-first architecture (everything on 127.0.0.1)

Soon:
- eBPF kernel hooks for TCP/IP packet header mutation
- Behavioral noise generation via automated browser profiles
- Profile rotation and session fragmentation

## What This Isn't

- Not a VPN
- Not Tor
- Not "privacy mode"
- Not invisibility
- Not trying to hide you

We're trying to make you statistically useless.

## How It Works

Three layers (two implemented, one in development):

**Layer 0: Local MITM (Intercept)**
- Runs on localhost
- Intercepts HTTPS traffic
- Rewrites headers (User-Agent, Accept, sec-ch-ua, etc.)
- Injects JavaScript spoofing layers
- Manages browser profiles

**Layer 1: Kernel Modification (Distort)** `[in development]`
- eBPF hooks for packet manipulation
- TCP/IP metadata randomization
- TTL/ToS field modification
- JA3/JA4 fingerprint mutation

**Layer 2: Behavioral Noise (Obfuscate)** `[in development]`
- Automated profile simulation
- Plausible but contradictory traffic generation
- Cookie/SSO token fragmentation
- Cross-site correlation breaking

## State of v.01

This is experimental. Core functionality works:
- Consistent spoofing across amiunique.org, browserleaks.com, coveryourtracks.eff.org
- Profile-based fingerprint mutation
- Working login flows (Firefox mostly stable, Chrome breaks frequently)
- CSP preservation during script injection

Expect breakage. Chrome is fussy, Firefox less so.

## Critical Warnings

- **This terminates TLS.** Your mitmproxy CA cert can see passwords and session tokens. Never share it. Never.
- **Use throwaway accounts** for any testing involving login flows.
- **Read the code** before running it. Every line. This is a MITM proxy.
- **Security issues:** 404mesh@proton.me

## Requirements

- Python (compatible with mitmproxy)
- mitmproxy
- A functioning understanding of what you're running

## Installation

See README.md for setup instructions.

## The Point

The Tor Project has done irreplaceable work. But exit nodes get blocked, proxies break, and the barrier to entry is high. Privacy tools need to evolve beyond hiding. We need to make the data itself meaningless.

404 is one attempt. There will be others. The goal isn't to replace existing tools. The goal is to make tracking economically and statistically impossible. To drown the signal in noise. To fragment identity so thoroughly that correlation becomes worthless.

Decentralization isn't just a technical goal. It's a rejection of biopolitical control. It's dismantling the census, brick by brick.

This is v.01. It's a start.

## License

AGPL-3.0