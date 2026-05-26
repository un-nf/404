# STATIC Proxy
***Synthetic Traffic and TLS Identity Camouflage***

<div align="center">

**A Rust MITM proxy for profile-driven browser-family shaping across transport and browser surfaces**

[![Rust](https://img.shields.io/badge/rust-1.76%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](../LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-HTTP%2F1.1%20%7C%20HTTP%2F2-green.svg)]()

[Workspace README](../README.md) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Limitations](#limitations)

</div>

---

## STATIC

A profile-driven MITM proxy that shapes two layers of your connection:

- outbound transport behavior such as headers, ALPN, TLS hello variants, and HTTP/2 behavior
- injected browser behavior such as navigator identity, canvas, WebGL, audio, iframe propagation, and worker bootstrap state

The architecture is centered on browser families. The injected script layer is designed around Chromium-family variants such as Chrome, Edge, and Brave, and Firefox-family variants such as Firefox and future Mullvad-style profiles.

STATIC itself does not enforce native-browser parity. If an operator manually chooses the wrong family, the proxy will not stop them. Best practice is to stay within the native rendering-engine family and only vary the branded identity inside that family. External wrappers such as [404-APP](https://404privacy.com/pricing/) can apply stricter selection policy on top of STATIC.

## Core Elements

### 1. Shared profile state

STATIC loads one `ProfileStore` at startup and shares it between:

- the proxy request pipeline
- the localhost control plane

That keeps profile selection coherent. The request pipeline and the control API are reading and mutating the same in-memory catalog and active profile state.

### 2. Explicit proxy startup

Proxy mode does not start in an ambiguous identity state. A profile must be selected explicitly through CLI or config. STATIC will list available profiles, but it will not silently pick one for standalone proxy startup.

### 3. Family-aware browser shaping

Profiles describe family and variant explicitly. STATIC uses that contract in:

- profile validation
- injected-script config
- worker bootstrap
- iframe propagation
- TLS/profile coherence checks

### 4. Seeded persona materialization

Profiles are not just loaded raw. Any `seeded_overlays` are materialized into one concrete process-lifetime persona, which is then passed into the browser-side script layer and the transport layer.

---

## Quick Start

### Repository build

Build the JS bundle first:

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

List the discovered profiles:

```bash
cd src/STATIC_proxy
cargo run -- --list-profiles
```

On Linux, host `cargo run` depends on a shared `libclang` installation because
native TLS dependencies use `bindgen`. If you see `Unable to find libclang`,
install `libclang-dev` and export:

```bash
export LIBCLANG_PATH="$(bash ../../scripts/resolve-libclang-path.sh)"
```

When you run without a config file on Linux, the CLI defaults use the file-backed
keystore because Linux/WSL hosts often do not have a usable desktop keychain
service. The explicit sample configs below still keep `keychain` as the general
native-desktop default.

Run with the sample config and an explicit profile:

```bash
cd src/STATIC_proxy
cargo run -- --config config/static.example.toml --profile chrome-windows
```

For local WSL/Linux runs that need a config file, switch the sample keystore mode
to `file` or use the WSL/runtime config emitted by the desktop app.

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

The repository ships multiple config examples:

- [config/static.example.toml](config/static.example.toml) for local standalone usage
- [config/app.config.toml](config/app.config.toml) for app-managed startup defaults
- [config/static.chrome.toml](config/static.chrome.toml) for a pinned Chromium-family example

`static.example.toml`:

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

Behavior:

- the control plane binds on `listener.bind_port + 2`
- if no config file is used, CLI defaults use port `8443` for the listener and `8444` for HTTP/3
- the control plane can be configured explicitly with an optional `[control]` section
- if `control.token_path` is set, control endpoints require the `X-404-Control-Token` header
- managed CA material is owned by STATIC and stored under the OS app-data directory
- legacy `tls.ca_cert_path`, `tls.ca_key_path`, and `tls.cache_dir` are not general override points

Optional control-plane config:

```toml
[control]
bind_address = "127.0.0.1"
token_path = "./control-token"
```

---

## Profiles

Bundled browser profiles live in [profiles](profiles):

- `chrome-windows.json`
- `edge-windows.json`
- `firefox-windows.json`
- `manifest.json`

Each profile can contribute:

- HTTP header config
- JavaScript fingerprint config
- TLS hello variants and HTTP/2 settings
- Seeded overlay choices

The profile catalog exposed by STATIC includes:

- key
- display name
- family
- variant
- platform

### Profile selection

Best practice:

- Use Chromium-family profiles on Blink-family browsers
- Use Firefox-family profiles on Gecko-family browsers
- Vary the branded identity inside that family

> STATIC does not hard-enforce this policy. Manual operators are responsible for selecting the right profile.
---

## Architecture

### Repository structure

```text
src/STATIC_proxy/
├── Cargo.toml                      # Rust crate manifest for STATIC
├── assets/
│   └── js/
│       ├── behavioral_noise_v1.js  # Runtime-side behavioral noise helper
│       ├── dist/                  # Built browser-side bundle embedded by Rust
│       └── src/
│           ├── capabilities/
│           ├── contexts/
│           ├── core/
│           ├── evasion/
│           ├── identity/
│           ├── privacy/
│           ├── spoofing/
│           └── runtime.js
├── build/                         # Node/esbuild workspace for runtime.bundle.js
│   ├── build.js
│   └── package.json
├── build.rs                       # Rust build hook for embedded assets
├── certs/                         # Local development certificates and fixtures
├── config/
│   ├── app.config.toml
│   ├── static.chrome.toml
│   └── static.example.toml
├── profiles/
├── src/
│   ├── app.rs
│   ├── assets.rs
│   ├── behavior/
│   ├── control.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── telemetry.rs
│   ├── config/
│   ├── keystore/
│   ├── proxy/
│   ├── tls/
│   └── utils/
└── target/                        # Local build output when compiling in place
```

### Process modes

STATIC can run in two modes:

- `proxy`: full data plane + control plane
- `control`: localhost control sidecar only

`app.rs` is the composition root. It loads the shared `ProfileStore`, constructs the stage pipeline, builds the proxy server, and starts the control plane with shared readiness and shutdown state.

### Data plane

The proxy path is split into explicit protocol classes:

- direct TLS interception
- HTTP CONNECT proxy tunneling
- plain HTTP proxy requests

`connection.rs` then chooses the appropriate downstream and upstream handling path, including:

- HTTP/1.1 sessions
- HTTP/2 sessions
- raw websocket tunneling
- local injected-script delivery (`/__static/runtime.js`)
- buffered HTML mutation only when response stages actually require it

### Stage pipeline

Deterministic request/response stage:

1. `HeaderProfileStage`
2. `BehavioralNoiseStage`
3. `CspStage`
4. `JsInjectionStage`
5. `AltSvcStage`

That order matters. Profile state has to exist before the injected script is configured, and CSP/JS mutation has to happen before Alt-Svc normalization finalizes the downstream response.

### Transport layer

`fetcher.rs` is the boundary between STATIC's profile model and what the `wreq` backend can express.

The transport plan passes through:

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

## Injected Script Layer

The browser-side script bundle is built from [assets/js/src/runtime.js](assets/js/src/runtime.js) into `assets/js/dist/runtime.bundle.js`.

Bootstrap order:

1. initialize the shared registry
2. capture native references
3. install `Function.prototype.toString` masking
4. capture nonce state
5. load browser-side config
6. initialize entropy
7. initialize policy
8. install identity, capability, spoofing, evasion, privacy, and iframe modules

### Shared registry

The shared registry lives under `window.__STATIC_RUNTIME__` and tracks:

- script version
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

The injected script mirrors:

- the shared registry
- nonce state
- a base set of globals
- `chrome` only for Chromium-family profiles
- selected prototype descriptors for navigator, screen, document, canvas, audio, and WebRTC surfaces

### High-entropy surfaces

- canvas
- WebGL
- audio
- event timing
- media devices
- speech
- WebRTC

These modules rely on shared entropy and materialized profile state.

---

## Production Guidance

### What belongs in STATIC

STATIC is responsible for:

- loading and applying browser profiles
- shaping transport behavior and browser-side behavior from those profiles
- exposing catalog/selection state over the localhost control plane

---

## Testing and Validation

Rust library tests:

```bash
cd src/STATIC_proxy
cargo test --lib --quiet
```

JS bundle rebuild:

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

- exact on-the-wire TLS parity is bounded by `wreq` and its TLS backend
- service workers and pre-existing workers remain outside the injected script's reach
- STATIC does not enforce native-family profile correctness for manual operators