# STATIC Proxy
***Synthetic Traffic and TLS Identity Camouflage***

<div align="center">

**A Rust MITM proxy for profile-driven browser-family shaping across transport and runtime surfaces**

[![Rust](https://img.shields.io/badge/rust-1.76%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](../LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-HTTP%2F1.1%20%7C%20HTTP%2F2-green.svg)]()

[Workspace README](../README.md) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Limitations](#limitations)

</div>

---

## What STATIC Is

STATIC is a profile-driven MITM proxy that shapes two layers at the same time:

- outbound transport behavior such as headers, ALPN, TLS hello variants, and HTTP/2 behavior
- injected runtime behavior such as navigator identity, canvas, WebGL, audio, iframe propagation, and worker bootstrap state

The current architecture is centered on browser families rather than cross-engine impersonation. In practical terms, that means the runtime is designed around Chromium-family variants such as Chrome, Edge, and Brave, and Firefox-family variants such as Firefox and future Mullvad-style profiles.

STATIC itself does not enforce native-browser correctness. If an operator manually chooses the wrong family, the proxy will not stop them. Best practice is to stay within the native rendering-engine family and only vary the branded identity inside that family. External wrappers such as 404-APP can apply stricter selection policy on top of STATIC, but that policy is intentionally outside this repository.

## Core Model

The current codebase is built around four ideas.

### 1. Shared profile state

STATIC loads one `ProfileStore` at startup and shares it between:

- the proxy request pipeline
- the localhost control plane

That is what makes runtime profile selection coherent. The request pipeline and the control API are reading and mutating the same in-memory catalog and active profile state.

### 2. Explicit runtime startup

Proxy mode does not start in an ambiguous identity state. A profile must be selected explicitly through CLI or config. STATIC will list available profiles, but it will not silently pick one for standalone proxy startup.

### 3. Family-aware runtime shaping

Profiles now describe family and variant explicitly. The runtime uses that contract in:

- profile validation
- JS runtime config
- worker bootstrap
- iframe propagation
- TLS/profile coherence checks

### 4. Seeded persona materialization

Profiles are not just loaded raw. Any `seeded_overlays` are materialized into one concrete process-lifetime persona, which is then passed into the runtime and transport layers.

---

## Quick Start

### Repository build

Build the JS runtime bundle first:

```bash
cd src/STATIC_proxy/build
npm install
npm run build
```

Run the Rust tests:

```bash
cd src/STATIC_proxy
cargo test --lib
```

List the discovered runtime profiles:

```bash
cd src/STATIC_proxy
cargo run -- --list-profiles
```

Run with the sample config and an explicit profile:

```bash
cd src/STATIC_proxy
cargo run -- --config config/static.example.toml --profile chrome-windows
```

### Standalone binary usage

If no config file is provided, STATIC falls back to built-in CLI defaults and looks for a `profiles` directory beside the executable.

Example:

```bash
static --profiles-path .\profiles --profile edge-windows
```

Useful CLI flags:

- `--list-profiles`
- `--profile <name>`
- `--profiles-path <path>`
- `--bind-address <ip>`
- `--bind-port <port>`
- `--mode proxy|control`
- `--json-logs`

---

## Configuration

The repository sample config is [config/static.example.toml](config/static.example.toml).

Current sample defaults:

```toml
[listener]
bind_address = "127.0.0.1"
bind_port = 4040
proxy_protocol = "tls"

[tls]
keystore = { mode = "keychain", service = "404.static_proxy", account = "ca_key" }

[pipeline]
profiles_path = "../profiles"
js_debug = false
alt_svc_strategy = "normalize"
body_limits = { max_request_body_bytes = 16777216, max_response_body_bytes = 33554432, max_decompressed_html_bytes = 16777216 }

[http3]
enabled = false
bind_address = "127.0.0.1"
bind_port = 4041

[telemetry]
mode = "stdout"
```

Important runtime behavior:

- the control plane binds on `listener.bind_port + 2`
- if no config file is used, CLI defaults use port `8443` for the listener and `8444` for HTTP/3
- managed CA material is owned by STATIC and stored under the OS app-data directory
- legacy `tls.ca_cert_path`, `tls.ca_key_path`, and `tls.cache_dir` are not general override points anymore

---

## Profiles

Current bundled runtime profiles live in [profiles](profiles):

- `chrome-windows.json`
- `edge-windows.json`
- `firefox-windows.json`
- `manifest.json`

Each runtime profile can contribute:

- header shaping rules
- fingerprint/runtime config
- TLS hello variants and HTTP/2 settings
- seeded overlay choices for process-lifetime persona materialization

The profile catalog exposed by STATIC includes:

- key
- display name
- family
- variant
- platform

### Selection guidance

Best practice is simple:

- use Chromium-family profiles on Chromium-family browsers
- use Firefox-family profiles on Firefox-family browsers
- vary the branded identity inside that family rather than pretending to be a different engine

STATIC does not hard-enforce that policy. Manual operators are responsible for selecting the right profile. That separation is intentional.

---

## Architecture

### Repository structure

Current high-value paths:

```text
src/STATIC_proxy/
├── assets/
│   └── js/
│       ├── dist/                  # Built runtime bundle embedded by Rust
│       └── src/
│           ├── capabilities/
│           ├── contexts/
│           ├── core/
│           ├── evasion/
│           ├── identity/
│           ├── privacy/
│           ├── spoofing/
│           └── runtime.js
├── build/                         # esbuild entrypoint for runtime.bundle.js
├── config/
│   └── static.example.toml
├── profiles/
├── src/
│   ├── app.rs
│   ├── assets.rs
│   ├── control.rs
│   ├── main.rs
│   ├── telemetry.rs
│   ├── config/
│   ├── keystore/
│   ├── proxy/
│   ├── tls/
│   └── utils/
└── tests/
```

### Runtime modes

STATIC can run in two modes:

- `proxy`: full data plane + control plane
- `control`: localhost control sidecar only

`app.rs` is the composition root. It loads the shared `ProfileStore`, constructs the stage pipeline, builds the proxy server, and starts the control plane with shared readiness and shutdown state.

### Data plane

The proxy path is currently split into explicit protocol classes:

- direct TLS interception
- HTTP CONNECT proxy tunneling
- plain HTTP proxy requests

`connection.rs` then chooses the appropriate downstream and upstream handling path, including:

- HTTP/1.1 sessions
- HTTP/2 sessions
- raw websocket tunneling
- local runtime asset delivery (`/__static/runtime.js`)
- buffered HTML mutation only when response stages actually require it

### Stage pipeline

The current request/response stage order is deterministic:

1. `HeaderProfileStage`
2. `BehavioralNoiseStage`
3. `CspStage`
4. `JsInjectionStage`
5. `AltSvcStage`

That order matters. Profile state has to exist before the injected runtime is configured, and CSP/JS mutation has to happen before Alt-Svc normalization finalizes the downstream response.

### Transport layer

`fetcher.rs` is the boundary between STATIC's profile model and what the current `wreq` backend can actually express.

The runtime currently passes through:

- cipher-suite ordering
- signature-algorithm ordering
- supported-group ordering
- ALPN
- extension ordering
- delegated credentials
- ALPS settings where applicable
- record-size and session-resumption controls

Important caveat: exact wire parity is still bounded by the capabilities of `wreq` and its TLS backend.

### Profile store and control plane

The control plane in [src/control.rs](src/control.rs) exposes:

- `GET /status`
- `GET /ca/status`
- `POST /ca/init`
- `POST /stop`
- `GET /telemetry/snapshot`
- `GET /profiles/catalog`
- `GET /profiles/active`
- `POST /profiles/select`
- `POST /profiles/validate`

The profile loader in `header_profile.rs` recursively discovers profile JSON, builds catalog metadata, materializes seeded overlays, and keeps active profile state in memory for both the data plane and the control API.

---

## JS Runtime

The current JS runtime is built from [assets/js/src/runtime.js](assets/js/src/runtime.js) into `assets/js/dist/runtime.bundle.js`.

It is a bootstrap pipeline, not a loose set of independent patches.

Current high-level bootstrap order:

1. initialize the runtime registry
2. capture native references
3. install `Function.prototype.toString` masking
4. capture nonce state
5. load runtime config
6. initialize entropy
7. initialize policy
8. install identity, capability, spoofing, evasion, privacy, and iframe modules

### Runtime registry

The shared registry lives under `window.__STATIC_RUNTIME__` and tracks:

- runtime version
- config
- policy
- entropy state
- native references
- loaded modules
- nonce state

### Worker handling

Worker and SharedWorker constructors are wrapped through blob-URL bootstrap scripts.

That bootstrap path is where STATIC can shape worker-visible identity surfaces such as:

- `navigator.userAgent`
- `platform`
- `languages`
- `hardwareConcurrency`
- family-aware Chromium `userAgentData` and `vendorFlavors`

This constructor-wrapping model is the only realistic place to affect worker scope after creation.

### Iframe propagation

Iframe propagation is same-origin and selective.

The runtime mirrors:

- the shared runtime registry
- nonce state
- a base set of globals
- `chrome` only for Chromium-family profiles
- selected prototype descriptors for navigator, screen, document, canvas, audio, and WebRTC surfaces

### High-entropy surfaces

Current high-entropy runtime modules include:

- canvas
- WebGL
- audio
- event timing
- media devices
- speech
- WebRTC

These modules now rely on shared entropy and materialized profile state rather than completely unrelated per-surface randomness.

---

## Production Guidance

### What belongs in STATIC

STATIC is responsible for:

- loading and applying runtime profiles
- shaping transport and runtime behavior from those profiles
- exposing catalog/selection state over the localhost control plane
- documenting current implementation limits truthfully

### What does not belong in STATIC

STATIC is not the policy layer that decides what a user should be allowed to select.

If a proprietary wrapper wants to auto-detect the native browser family and force compatible profile choices, that belongs in the wrapper. STATIC intentionally stays lower-level.

---

## Testing and Validation

Rust library tests:

```bash
cd src/STATIC_proxy
cargo test --lib --quiet
```

JS runtime bundle rebuild:

```bash
cd src/STATIC_proxy/build
npm run build
```

Profile catalog check:

```bash
cd src/STATIC_proxy
cargo run -- --list-profiles
```

These should be part of any release hygiene for this subtree.

---

## Limitations

Important current limits:

- exact on-the-wire TLS parity is bounded by `wreq` and its TLS backend
- service workers and pre-existing workers remain outside the injected runtime's reach
- STATIC does not enforce native-family profile correctness for manual operators
- runtime shaping is strongest where the proxy owns both transport and injected JS entry points

These limits are implementation boundaries, not hidden caveats.

---

## Current Direction

The direction of the live tree is straightforward:

- keep the family model
- keep explicit runtime profile state
- keep seeded persona materialization
- keep worker and iframe coherence
- reduce cross-engine impersonation debt
- stay honest about backend limits and scope boundaries

That keeps the codebase aligned with the current architecture instead of carrying old Firefox-vs-Chromium impersonation complexity forever.
