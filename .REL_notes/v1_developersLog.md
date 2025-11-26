# STATIC v1 · The Proxy That Keeps Its Story Straight

> This isn’t a “we stood up a MITM” brag. It’s the Cliff Notes from three days, 60 hours, and an unhealthy number of BrowserLeaks tabs—from the first rustls panic to the moment reCAPTCHA finally stopped heckling me.

`legacy.md` still has the blow-by-blow. This is the CFO-meets-speechwriter pass: what mattered, why it mattered, and how every layer now tells the same persona story without flinching.

---

## The Thesis

- **Full-stack fingerprint control** only works if the transport is predictable before the persona gets creative.

---

## Pillar 1 · Trust & TLS Machinery

- **rustls 0.23 + tokio-rustls 0.26** backbone, every PKI type migrated to `pki_types`. aws-lc is the grown-up crypto engine (bring CMake + NASM), `ring` has not been wired yet.

- **Custom `ResolvesServerCert`** with DashMap cache, per-host keys, 24-hour leaf rotation, and explicit “certificate expired, regenerating” logs.

- **On-demand TLS planner** driven by profile-defined cipher catalogs, weighted hello variants, supported groups, key-share order, ALPN hints, padding directives, JA3/JA4 fingerprints. Deterministic UUIDv7/flow seeds.

- **Capability clipping on purpose**: planner tells you exactly which cipher rustls/aws-lc can’t emit (RSA, CBC, PQ hybrids). ALPN clamps to `h2`/`http/1.1` until QUIC is implemented.

---

## Pillar 2 · A Proxy That Actually Moves Traffic

- **CONNECT is finally grown-up**. Browser says `CONNECT host:port`, we parse it, ACK it, and stash `connect_target` in FlowMetadata for routing + telemetry.

- **Upstream TLS client** negotiates via `rustls::ClientConfig` with real trust roots and SNI, returning `TlsStream<TcpStream>` so origin servers see an actual ClientHello.

- **HTTP/1.1 engine** parses request lines, normalizes chunked bodies, respects bodyless codes (1xx/204/205/304), runs request/response stages, rewrites headers, and sends the mutated response back. `send_request_to_upstream()` fires before any duplex copy.

- **HTTP/2 engine** terminates client h2 via `h2::server`, spins a task per stream, buffers safely, and picks h2-h2 or h2-h1 fallback based on upstream ALPN. Manual `release_capacity` keeps flow control honest, and pseudo-headers/hop-by-hop fields get sanitized so segments stay alive.

---

## Pillar 3 · Profiles, Pipeline, and Persona Discipline

- **StaticConfig + profile JSON** are the control plane. Profiles hot-reload via `notify` and carry header personas, TLS catalogs, behavioral envelopes, JS toggles, vendor strings, viewport/DPR, media capabilities, etc.

- **StagePipeline order mirrors the legacy Python addon**: `HeaderProfileStage → BehavioralNoiseStage → CspStage → JsInjectionStage → AltSvcStage`.

    - *HeaderProfileStage* enforces remove → replace → replaceArbitrary → replaceDynamic → set → append, stuffing the full fingerprint config into Flow metadata for downstream consumers.

	- *BehavioralNoiseStage* only mutates envelopes when JS already wrapped the body, keeping server-visible noise in sync with client-visible cues.

	- *CspStage* rewrites policies with nonce reuse, per-origin guardrails, and pass-through for fragile giants (YouTube/Drive/Google auth). Hashes appear only when allowed; some hosts get `'unsafe-inline'`.

	- *JsInjectionStage* decompresses responses if needed, injects the entire JS stack at the earliest safe `<head>` slot (synthesizing tags when missing), recompresses, and updates headers.

	- *AltSvcStage* normalizes or strips HTTP/3/quic advertisements so BrowserLeaks only sees the transports we actually terminate.

- **BehavioralNoiseEngine** tags flows with deterministic envelopes, coordinates with the JS behavioral shim, and keeps timing cadence + hidden metadata lined up.

---

## Pillar 4 · Browser Surface & Spoof Stack

- **Bootstrap (0bootstrap_v4)** hooks canvas, OffscreenCanvas, and dynamic script creation *before* any page code. It propagates into iframes, guards eval/Function, captures CSP nonces, and exposes sentinel globals (`__static_bootstrap_active`).

- **Globals shim (1globals_shim_v4)** owns navigator/screen/performance/storage/gpu/media/battery/network surfaces, memoizes `navigator.plugins`/`mimeTypes`, normalizes missing APIs into deterministic proxies, and enforces viewport/DPR straight from profile config.

- **Config layer v3** bridges Rust -> JS (`__STATIC_CONFIG__`, `__STATIC_SESSION_ID`) so the fingerprint bundle, globals shim, and behavioral engine all pull from the same persona.

- **Fingerprint spoof v4** now covers navigator props, canvas/WebGL/audio noise, event timing jitter, Math micro-noise capped at 1e-10 *(in development. Currently commented out because it breaks captcha)*, SpeechSynthesis voices, MediaDevices/Gamepad IDs, WebGPU adapters, automation evasion, and iframe propagation. High-risk surfaces (permissions, notifications, geolocation) migrated into globals shim to match header-level personas.

- **Canvas guard strategy** seeds per-origin RNGs, wraps `getImageData`/`toDataURL`/Offscreen hooks before DOM load, and lets profiles dictate stride/delta/alpha via `fingerprint.canvas_noise.strategy`. Fingerprint spoof defers to the guard to avoid double jitter.

- **Behavioral JS shim** follows Rust’s noise plan so timing envelopes and metadata fields stuffed inside HTTP bodies stay believable.

---

## Pillar 5 · Honest Guardrails

- **ECH**: Browsers disable it when a user-installed CA is present. STATIC leans into that reality, documents the BrowserLeaks readout, and outlines what real ECH support would require (DNS HTTPS RRs, HPKE, rustls changes, cooperating origins).

- **HTTP/3**: Config scaffolding + planner hooks exist, but there’s no QUIC listener yet. ALPN never advertises `h3` until both client and upstream legs have a real data plane.

- **Streaming bodies**: HTTP/1.1 + HTTP/2 still buffer requests/responses before mutation. It’s a limitation, it’s documented, and it stays on the roadmap until the stage API can handle streaming.

- **GREASE/RSA/PQ**: rustls/aws-lc can’t emit them today. Planner logs the drop so JA3/JA4 mismatches aren’t a mystery. Custom TLS backend? Might as well...

---

## Under-the-Hood Work That Makes It Feel Finished

- **DNS resolver** with IPv4/IPv6 support, jittered retries, caching, and Windows `WSANO_DATA` fallback to blocking `getaddrinfo`.

- **Alt-Svc normalization** with remove/redirect strategies plus unit tests so server doesn't ever see http/3 advertised.

- **Certificate TTLs** (24h) with automatic regeneration, lazy eviction, and transparent logging.

- **Upstream boring toggle** (feature flag) so operators who need OpenSSL-only suites can flip `tokio-boring` without rewriting the pipeline.

- **Asset pipeline** minifies JS bundles at load, wraps the minifier in `catch_unwind`, and falls back to raw sources if anything panics—startup never dies because a script was weird.
---

## What to Expect Next

1. **HTTP/3 data plane** once the QUIC listener + upstream client land; planner already knows how to tell the truth when it exists.

2. **Streaming stage API** so massive uploads/downloads stop hitting RAM first.

3. **Attestation & CA hardening** (TPM/DPAPI, offline root + online intermediate) pulled straight from the legacy notes once TLS parity beds in.

Appreciate you reading the polished journal. The messy one’s still [here](.REL_notes/leg/devLog.md) if you want to relive every “why is this on fire?” moment.