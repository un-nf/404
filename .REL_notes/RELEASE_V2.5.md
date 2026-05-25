# v2.5 Release Notes

## What Changed

### Shared profile state

STATIC loads one `ProfileStore` at startup and shares it between the proxy pipeline and the localhost control plane. Previously these two subsystems discovered and read profile state independently. Now they operate on the same in-memory object, which makes active-profile switching possible.

The control plane exposes four new profile management endpoints alongside the existing lifecycle and CA endpoints:

```
GET  /profiles/catalog
GET  /profiles/active
POST /profiles/select
POST /profiles/validate
```

### Explicit startup requirements

Proxy mode refuses to start without an explicit active profile.

Profile selection at startup comes from `--profile <name>` or `pipeline.default_profile` in config. Additional CLI flags added:

- `--list-profiles` — inspect the discovered catalog without starting proxy mode
- `--profiles-path <path>` — point discovery at an arbitrary directory
- `--bind-address`, `--bind-port` - override listener settings without editing config

CA material and certificate cache paths are resolved under the OS app-data directory. The legacy TLS path fields still work as compatibility inputs but are no longer the primary mechanism.

### Family-first identity model

Profiles carry explicit identity metadata at two levels:

```
profile_identity.family / profile_identity.variant / profile_identity.platform
fingerprint.browser_family / fingerprint.browser_variant
```

STATIC treats family as the primary identity boundary and variant as the branded flavor on top. 

Shipped families: `firefox-like` and `chromium-like`. Older fields like `browser_type` still work as fallback inputs.

### Seeded profile materialization

The profile loader recursively discovers profile JSON files rather than assuming a flat layout.

Before a discovered profile is stored, STATIC materializes any `seeded_overlays` into a concrete persona and records the result in `selected_overlays`. STATIC does not just select a profile file; it selects and freezes a specific persona shape for the lifetime of the process.

### Deterministic stage pipeline

Stage execution on the Rust side is deterministic:

1. Header/profile application
2. Behavioral metadata
3. CSP handling
4. JS injection
5. Alt-Svc handling

JS injection targets successful HTML responses, decompresses only when necessary, and passes browser-side config through a `data-static-config-b64` attribute rather than relying on broader in-place response mutation.

On the JS side the injected script boots in a fixed order: registry init, native reference capture, toString masking, CSP nonce capture, config load and validation, entropy init, policy init, then identity/capability/spoofing/evasion/privacy/iframe modules behind policy gates.

The global registry contract is explicit through `__STATIC_RUNTIME__`. That shared object holds version, config, policy, entropy, native references, loaded-module markers, and nonce state.

### Worker and iframe coherence

Worker construction injects a bootstrap source that embeds resolved family/variant state and a reduced identity snapshot into the worker entry path. 

Classic workers only — module workers are passed through untouched because replacing their script URL with a blob URL breaks root-relative and relative imports.

Iframe propagation synchronizes same-origin-safe frames and copies prototype descriptors directly from parent patched prototypes into child window equivalents rather than re-running the full injected script.

### Entropy

`core/entropy.js` derives entropy state the process startup salt, the current document origin, and selected fingerprint attributes. The result is stable within one STATIC process lifetime, origin-aware, and rotated on restart.

### Canvas and audio spoofing

Canvas noise is seeded from the canvas hash, session ID, current origin, a sampled content signature from actual canvas bytes, and the specific export operation. 

Noise is stable on refresh for the same origin within one STATIC startup and rotates on restart.

Audio spoofing resolves a hardware persona from either configured hardware profiles or seeded hardware-class selection derived from media device labels. The persona drives `sampleRate`, `baseLatency`, `outputLatency`, channel layout, and render transforms for analyser, offline, and worklet-visible buffers.

### Transport routing and upstream negotiation

Inbound routing distinguishes between direct TLS interception, HTTP CONNECT proxy traffic, and plain HTTP proxy traffic. Plain HTTP absolute-form requests go through a dedicated session path rather than being misclassified.

On the outbound side, instead of selecting one TLS hello variant and failing hard on rejection, STATIC can retry retryable connect-stage failures with alternate ALPN-compatible variants. An upstream RST can mean "this hello variant was rejected" rather than "the whole request is broken."

The fetcher receives cipher suite ordering, signature algorithm ordering, supported-group ordering, ALPN, extension ordering, delegated credentials, ALPS settings, and session-resumption knobs from the transport plan. Exact wire parity remains bounded by what `wreq` and its TLS backend can express.

### Shipped profile refresh

Shipped Windows profiles are aligned to:

- Firefox 149.0.2
- Chrome 147.0.7727.102
- Edge 147.0.3912.72

---

## Validation

- `cargo test --lib --quiet`: 64 passed, 0 failed
- `npm run build`: `assets/js/dist/runtime.bundle.js` rebuilds cleanly