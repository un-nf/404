## Dependency Management & Rustls Ecosystem (Updated: Session 1)

### Rustls + tokio-rustls Version Lockstep
- **Always pair compatible versions.** Example: `tokio-rustls 0.26` requires `rustls 0.23`.
- Check [tokio-rustls changelog](https://github.com/rustls/tokio-rustls/releases) when bumping versions.
- "Unresolved import" or "missing method" errors == version mismatch between rustls/tokio-rustls.

### Crypto Backend: aws-lc vs ring
- **rustls 0.23+** defaults to `aws-lc-rs` backend, which requires native build tools on Windows (CMake, NASM).
- **Workaround for dev velocity:** enable the `ring` backend with `rustls = { version = "0.23", features = ["log", "ring"] }` to avoid native toolchain setup.
- Import path changes: `rustls::crypto::ring::sign::any_supported_type` (ring) vs `rustls::crypto::aws_lc_rs::sign::any_supported_type` (aws-lc).
- Cipher suite constants in rustls 0.23 live under the backend module: use `rustls::crypto::aws_lc_rs::cipher_suite::*` when aws-lc is enabled; do **not** flip on the `ring` feature yet.

### PKI Types Migration (rustls 0.21 -> 0.23)
- Old: `rustls::Certificate`, `rustls::PrivateKey` at crate root.
- New: `rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName}`.
- **Key wrapping:** rcgen outputs `Vec<u8>` for keys. Correct conversion path:  
  `Vec<u8>` -> `PrivatePkcs8KeyDer::from(...)` -> `PrivateKeyDer::from(...)`.
- **SNI extraction:** In 0.23, `ServerConnection::server_name()` returns `Option<&str>`, not enum. Just call `.map(ToOwned::to_owned)`.

### Debug Trait for TLS Structs
- `ResolvesServerCert` trait in rustls 0.23 requires `Debug` bound.
- If a struct contains non-Debug types (e.g., `rcgen::Certificate`), implement custom `Debug` manually:
  ```rust
  impl std::fmt::Debug for MyStruct {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
          write!(f, "MyStruct {{ field: <opaque> }}")
      }
  }
  ```

### rcgen PEM Feature
- If using `rcgen::Certificate::serialize_pem()` or CA loading helpers, enable the `pem` feature:  
  `rcgen = { version = "0.12", features = ["pem"] }`.
- Without it, you'll hit "method not found" errors on PEM serialization calls.

---

## TLS Handshake Architecture (connection.rs)

### ServerConfig Builder Pattern (0.23)
- Use `.with_safe_defaults()` instead of individual cipher/kx/protocol methods (those were removed).
- Set resolver and ALPN *after* building the base config:
  ```rust
  let mut config = ServerConfig::builder()
      .with_safe_defaults()
      .with_no_client_auth()
      .with_cert_resolver(resolver);
  config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
  ```
- Don't try to mutate `cert_resolver` as a field before calling the final builder method.

### SNI Extraction
- **Correct access:** `TlsStream::get_ref()` returns `(TcpStream, ServerConnection)`. Use `.1` for the `ServerConnection`.
- **0.23 API:** `conn.server_name()` returns `Option<&str>`, not an enum. No pattern matching needed.

### On-Demand Cert Resolver
- Must implement `ResolvesServerCert` trait (requires `Debug`, `Send`, `Sync`).
- Resolver runs synchronously during handshake, so `TlsProvider::certified_key()` is blocking (fine, it's cached).
- Fallback SNI (`static.local`) prevents panics when client omits SNI (rare but possible with curl, openssl s_client).

---

## Certificate Management (tls/cert.rs)

### TlsProvider Caching Strategy
- `DashMap<String, Arc<CertifiedKey>>` allows lock-free concurrent reads/writes.
- Cache key = SNI hostname (lowercase, no port).
- No TTL or eviction policy yet; memory grows unbounded with unique SNIs (acceptable for MITM use case, but document this).

### CA Loading/Generation
- **Load path:** `CertificateParams::from_ca_cert_pem()` does NOT exist in rcgen 0.12. User will need to parse PEM manually (e.g., `rustls_pemfile`) and reconstruct params, or generate fresh CA on first run.
- **Generate path:** Writes PEM cert + key to disk for reuse across proxy restarts. Ensures browsers can trust the CA once imported.

### Leaf Certificate Issuance
- `serialize_der_with_signer()` returns a single DER blob (leaf cert signed by CA).
- Chain must include both leaf and issuer for browsers to validate: `vec![leaf_der, issuer_der]`.
- Signing key is derived from leaf's private key (not CA key), which is correct for server auth.

---

## Common Build Errors & Fixes

### `cargo` not recognized in PowerShell
- Symptom: `cargo: The term 'cargo' is not recognized...`
- Root cause: Rust toolchain installed but PATH not updated in current PowerShell session.
- Fix: Use absolute path `C:\Users\<user>\.cargo\bin\cargo.exe` or restart PowerShell to pick up updated PATH.

### "Missing dependency: cmake"
- Symptom: `aws-lc-sys` build fails with "Missing dependency: cmake".
- Root cause: rustls 0.23+ defaults to `aws-lc-rs` backend, which requires CMake and NASM.
- Fix: Install CMake/NASM and add to PATH, or switch to `ring` backend (see "Crypto Backend" above).

### "no `ServerName` in the root"
- Symptom: `use rustls::ServerName;` fails with "no ServerName in the root".
- Root cause: rustls 0.22+ moved `ServerName` to `pki_types` module.
- Fix: `use rustls::pki_types::ServerName;`

### "`PrivateKeyDer` is not implemented for `Vec<u8>`"
- Symptom: `PrivateKeyDer::from(vec![...])` fails.
- Root cause: rustls pki_types require specific key formats (PKCS#8, PKCS#1, SEC1).
- Fix: Wrap raw bytes in format-specific type first: `PrivatePkcs8KeyDer::from(...)` -> `PrivateKeyDer::from(...)`.

---

## Next Implementation Milestones

### HTTP Parsing (Priority 2)
- After TLS handshake completes, decrypt stream and parse HTTP/1.1 or H2 frames.
- Populate `Flow::RequestParts` with real method/uri/headers/body.
- Consider `hyper` or `httparse` for protocol handling (hyper already in deps).

### Upstream Client (Priority 3)
- `proxy/client.rs` currently returns `Err("not implemented")`.
- Need: connection pooling, SNI-aware dialing, ALPN negotiation mirroring client's choice.
- Reuse `TlsProvider` for upstream TLS fingerprinting (JA3 spoofing).

### Pipeline Stage Activation (Priority 2)
- Current stages run on placeholder `Flow` with empty request/response.
- Once HTTP parsing lands, stages will mutate real headers/bodies.
- Ensure `StagePipeline::process_*` methods are called in correct order (request -> response headers -> response body).

### Telemetry Enrichment (Priority 4)
- Log JA3/JA4 fingerprints alongside SNI.
- Add flow duration, upstream RTT, cache hit/miss for cert resolver.
- Consider structured logging (JSON) for production observability.

---

## Windows Development Notes

### Build Performance
- First `cargo build` downloads/compiles ~400 crates (aws-lc-sys alone is 9MB source).
- Subsequent builds are incremental (fast).
- `cargo check` is faster for iteration; use `cargo build --release` only for perf testing.

---

## HTTP CONNECT Tunnel Support (Session 2)

### Browser Proxy Protocol Flow
- **Standard browser behavior:** Send `CONNECT host:port HTTP/1.1` to establish tunnel, then TLS over tunnel.
- **Implementation:** Added `handle_connect_tunnel()` to parse CONNECT request, send `200 Connection Established`, return target host.
- **Protocol detection:** First byte peek now checks for `C` (CONNECT) in addition to `0x16` (TLS) and HTTP methods.

### Upstream Host Resolution Priority (CRITICAL FIX)
- **Problem:** After CONNECT tunnel, HTTP requests have relative URIs (`/search?q=...`), so `uri.host()` returns `None`. Proxy was connecting to hardcoded "example.com" fallback.
- **Root cause:** Browser sends `CONNECT www.google.com:443`, then `GET /search HTTP/1.1` (no host in URI). Must use SNI or CONNECT target for upstream.
- **Solution:** Priority chain for host resolution:
  1. `flow.metadata.tls_sni` (most reliable, extracted from TLS handshake SNI extension)
  2. `flow.metadata.connect_target` (from CONNECT tunnel, format "host:port")
  3. `flow.request.uri.host()` (for direct TLS without CONNECT, rare edge case)
  4. Fallback: "example.com" (should never hit this in use)

### FlowMetadata Extension
- Added `connect_target: Option<String>` field to `FlowMetadata` struct.
- Set in `handle_connection` after successful `handle_connect_tunnel()` call.
- Used for upstream host resolution and telemetry correlation.

### Browser Configuration
- Set browser to use **HTTP proxy** (not HTTPS proxy) at `127.0.0.1:8080`.
- Browser will automatically use CONNECT protocol for HTTPS destinations.
- Must trust `certs/static-ca.crt` in browser certificate store (Authorities/Root CA section).
- **Chrome/Edge:** Settings -> Privacy -> Security -> Manage certificates -> Authorities -> Import.
- **Firefox:** Settings -> Privacy -> View Certificates -> Authorities -> Import -> Trust for websites.

### Debugging CONNECT Issues
- **Symptom:** Browser loading indefinitely after tunnel establishment.
- **Log signature:** `CONNECT tunnel established` but then hangs on `connecting to upstream addr=example.com:443`.
- **Diagnosis:** Check if upstream host is being resolved correctly. Should match SNI, not fallback.
- **Fix:** Ensure `flow.metadata.tls_sni` is populated before upstream connection logic runs.

---

## Upstream TLS Client (Session 2 Completion)

### The Missing Piece
- **Problem:** Proxy was dialing plain TCP to HTTPS servers (like Google), causing connection hangs.
- **Root cause:** `UpstreamClient::connect()` returned `TcpStream` instead of TLS-wrapped stream.
- **Symptom:** Logs show `upstream connected` but then infinite loading (server waiting for TLS ClientHello).

### Implementation
- **TLS client config:** Uses `rustls::ClientConfig` with `webpki-roots` for system root certificate validation.
- **Server certificate validation:** Validates upstream servers against OS trust store (standard HTTPS client behavior).
- **SNI in client handshake:** Sets SNI to target hostname for proper routing and cert validation.
- **Return type:** Changed from `TcpStream` to `TlsStream<TcpStream>` (tokio-rustls client stream).

### Key Code Changes
- Added rustls imports: `ServerName`, `ClientConfig`, `TlsConnector`.
- Added `webpki-roots` for system root certificates (already in Cargo.toml).
- Modified `UpstreamClient::connect()` to:
  1. Dial TCP to upstream
  2. Load system root certificates
  3. Build `ClientConfig` with root validation + no client auth
  4. Create `TlsConnector` from config
  5. Perform TLS handshake with SNI
  6. Return encrypted `TlsStream`

### Generic Compatibility
- `proxy_data<C, U>()` already generic over `AsyncRead + AsyncWrite`, so no changes needed.
- Works with different stream types: `TlsStream<TcpStream>` (client) + `TlsStream<TcpStream>` (upstream).

### Production Notes
- **JA3 spoofing:** Not yet implemented. Current config uses rustls defaults (detectable as Rust TLS client).
- **ALPN:** Not configured. Upstream always uses HTTP/1.1 (no H2 yet).
- **Connection pooling:** Not implemented. Every request dials fresh (performance penalty).
- **Timeouts:** Not configured. Hangs indefinitely on slow/dead upstreams.

---

## Certificate TTL and Rotation (Session 2)

### Security Enhancement
- **Problem:** Cached certificates lived forever. If compromised, attacker could use them indefinitely.
- **Solution:** Time-based certificate expiration with automatic regeneration.

### Implementation Details
- **TTL:** 24 hours (configurable via `Duration::from_secs()`)
- **Cache structure:** `CachedCert { key: Arc<CertifiedKey>, created_at: Instant }`
- **Eviction strategy:** Lazy (expired entries stay in memory until next access, then regenerated)
- **Logging:** Debug log when cert expires: `certificate expired, regenerating`

### Security Benefits
- **Limited compromise window:** Stolen cert only works for 24 hours max
- **Automatic key rotation:** New ECDSA key pair generated on regeneration
- **Browser-compatible:** TTL long enough to not break typical sessions
- **No user impact:** Regeneration happens transparently on cache miss

### Performance Characteristics
- **Cache hit (valid cert):** O(1) lookup, instant return
- **Cache hit (expired cert):** O(1) lookup, treated as miss, triggers regeneration (~1-5ms)
- **Memory:** Expired entries not proactively cleaned (future enhancement: background GC task)

### Code Changes
- Added `Instant` and `Duration` imports from `std::time`
- Created `CachedCert` wrapper struct with timestamp
- Modified `CertificateCache` to store `CachedCert` instead of bare `Arc<CertifiedKey>`
- Updated `get()` to check `created_at.elapsed() < ttl` before returning
- Updated `insert()` to set `created_at = Instant::now()`

### Future Enhancements
- Make TTL configurable via `TlsConfig`
- Add background task to proactively evict expired entries
- Add metrics (cache hit rate, regeneration frequency, memory usage)
- Consider per-domain TTL overrides for high-security targets

---

## HTTP Request Forwarding (Session 2 - CRITICAL FIX)

### The Problem
- **Symptom:** TLS handshakes complete, upstream connects, but browser hangs forever loading.
- **Root cause:** Proxy parsed HTTP request from client but **never sent it to upstream**.
- **What was happening:** `proxy_data()` started bidirectional copy immediately after upstream connection, but upstream server was waiting for an HTTP request that never arrived.
- **Log signature:** `upstream TLS handshake complete` followed by silence, then `peer closed connection without sending TLS close_notify` after timeout.

### The Fix
- **Added:** `send_request_to_upstream()` function to serialize `RequestParts` back to HTTP/1.1 wire format.
- **Call order:** Connect upstream -> Send request -> Start bidirectional copy.
- **Request format:** `METHOD /path HTTP/1.1\r\n` + headers + `\r\n\r\n` + optional body.

### Implementation Details
- **Serialization:** Converts parsed `RequestParts` (method, URI, headers, body) back to HTTP/1.1 text format.
- **Header formatting:** Iterates `HeaderMap`, writes `Name: Value\r\n` for each.
- **Body handling:** Sends `RequestParts.body` bytes after headers if `Content-Length > 0`.
- **Flush:** Calls `AsyncWriteExt::flush()` to ensure request is sent before starting bidirectional copy.

### Why This Was Missed
- **Parsing confusion:** The code parsed the HTTP request from the client (for pipeline stages), but forgot that upstream also needs that request.
- **Bidirectional copy assumption:** `tokio::io::copy_bidirectional` copies data transparently, but it doesn't know about HTTP protocol—it can't inject the initial request.
- **Testing gap:** No integration test for full request/response cycle (only tested TLS handshake and connection establishment).

### Code Changes
- Added `send_request_to_upstream<W: AsyncWrite>()` function in `connection.rs`.
- Modified `handle_connection()` to call `send_request_to_upstream()` before `proxy_data()`.
- Added `AsyncWrite` to imports (was only importing `AsyncWriteExt`).

### Performance Notes


## Future Hardening / Attestation Ideas (Session 3)

### CA Key Protection Layers
- Import `static-ca` as a password-protected PFX into the Windows certificate store so CryptoAPI locks the private key under MachineKeys with ACLs instead of loose PEM files.
- Wrap the CA key with DPAPI or a TPM-bound secret; decrypt at runtime only when the proxy boots, keep the plaintext key in-memory only.
- Adopt an offline root / online intermediate CA split: keep the root offline, sign an intermediate for the proxy so key compromise is easier to revoke.

### Hardware / Remote Attestation Options
- Implement a `rustls::sign::SigningKey` wrapper that delegates to TPM-backed keys (via NCrypt or PKCS#11) so private key material never leaves hardware.
- Evaluate enclave or confidential-VM attestation if you ever need to prove to remote clients that STATIC is running a specific signed binary before they trust the CA.
- Consider client-side enforcement (browser extension / VPN agent) that pins the proxy CA only when a valid attestation token accompanies the connection.

### Operational Safeguards
- Enforce strict ACLs/BitLocker on `certs/`, avoid running proxy as Administrator, and isolate the runtime into a dedicated Windows user or VM.
- Rotate the CA regularly and purge it from trust stores after each testing campaign; TTL on leaf certs limits session replay but not CA compromise.
- Avoid verbose logging of decrypted flows unless encrypted at rest; treat process dumps as sensitive since they contain plaintext credentials.

## Profile Synchronization (Session 3)
- Treat `src/proxy/profiles.json` as the single source of truth for browser fingerprints.
- Whenever those profiles change, mirror the same JSON blocks into `static_proxy/profiles/*.json` so the Rust side stays aligned.
- Escaped wildcard sequence: `\\` in json before any `*`;

## TLS Profile Schema (Session 4)
- `static_proxy/profiles/*` now expose a `tls.schema_version = 2` block with a cipher catalog and weighted `hello_variants` so the Rust TLS planner can deterministically build ClientHello messages.
- Each variant carries ja3/ja4 strings from `profiles.json` + `TLS(Sheet1).csv`, extension ordering (hex codes + friendly names), ALPN list, supported groups, and resumption policy flags.
- `cipher_order.mode` accepts `catalog`, `catalog_default`, or `explicit` so you can reuse canonical cipher sets while still matching per-variant ordering from the CSV.
- TLS generator should pick a variant via weighted randomness, materialize ciphers from `cipher_catalog`, then emit extensions exactly in `extension_sequence` order (respect GREASE placeholders and padding strategies).
- Session ticket and padding knobs live next to each variant; no more global `cipher_rotations`. Any future profile changes must update both the catalog and affected variant blocks.
- Browsers like Chrome/Firefox reshuffle TLS 1.3 cipher ordering per connection; capture that by adding `cipher_permutations` (or per-variant shuffle groups) so runtime code samples one permutation, then recomputes the JA3 string from the emitted sequence.
- `cipher_permutations` includes `selection` (uniform/weighted) and `seed` hints (flow_id, rand) so runtime code can deterministically pick which TLS 1.3 ordering to emit while keeping TLS 1.2 suites anchored to the catalog order.

## Session 5 (Firefox Default + TLS Wiring)
- Config/pipeline now treat `pipeline.profiles_path` as a directory of single-profile JSON files; default selection targets `firefox-windows` unless config overrides it.
- HeaderProfileStage should continue stuffing the entire profile JSON into `flow.metadata.fingerprint_config` so TLS planner + JS addons share identical material.
- TLS planner derives variant/permutation deterministically from `Flow.id` when `seed = "flow_id"`, then maps cipher names onto rustls-supported suites, skipping ones rustls lacks.
- UpstreamClient::connect accepts an optional `TlsClientPlan` and applies ALPN/version/cipher ordering before dialing so JA3 alignment tracks the selected profile.
- TLS planner compilation requires importing `SupportedProtocolVersion` from the crate root; `rustls::version` only exposes the constants (`TLS12`, `TLS13`).
- Version constants in rustls are values, so borrow them (`&TLS13`, `&TLS12`) whenever a `&SupportedProtocolVersion` is required; otherwise the compiler yells.
- Profile selection keys now use the file stem (`firefox-windows.json` -> `firefox-windows`), while the human-readable fingerprint name is still emitted in telemetry; config defaults must match the stem, not the fingerprint label.
- Old profiles lacking `tls.schema_version` are treated as “no TLS plan” instead of crashing; planner returns `None` and Edge/Chrome legacy configs keep working.
- HTTP/2 isn’t wired through the pipeline yet, so TLS planner currently forces `http/1.1` ALPN even if a profile lists `h2`; once HTTP/2 parsing lands, relax this clamp.

## Session 6 (Cipher Coverage Reality)
- rustls 0.23 (aws-lc backend) exposes only TLS 1.2 ECDHE suites plus TLS 1.3 defaults; legacy RSA key-exchange or CBC-mode names in profiles will always log “cipher not supported”, so trim catalogs or treat those entries as documentation-only when computing JA3 fingerprints.

## Session 7 (ECH Disablement Under MITM)
- Enterprise roots (our static-ca) mark the connection as inspected, so modern browsers intentionally disable Encrypted Client Hello once they see a user-installed trust anchor; MITM works because the client now sends a plaintext ClientHello with real SNI.
- Since ECH encrypts the inner ClientHello with keys published by the origin’s DNS, the proxy can’t decrypt or re-encrypt it without holding the server’s private ECH config, so STATIC must keep ECH off until I design an upstream-cooperative scheme.
- Browser leak tools will therefore show `ECH Success = False`, `Outer SNI = real host`, and `Inner SNI = n/a` whenever the proxy is active; that’s expected and unavoidable for interception.
- Two mitigation paths: (1) upstream cooperation where the site shares its ECH private key or terminates traffic through a STATIC-aware fronting service, or (2) custom clients/browsers that keep ECH enabled but also hand the decrypted ClientHello to the proxy—both require coordinated deployments beyond drop-in browser proxy settings.
- Upstream-only spoofing (proxy speaks ECH to origin) is feasible in theory but needs three components we don’t have yet: (a) DNS HTTPS RR parser + cache for ECH configs, (b) HPKE-based ClientHelloOuter builder inside `UpstreamClient`, and (c) rustls support for client-side ECH (currently “planned” but not merged). Track rustls issue #1214 (or whichever is current) before attempting.

## Session 8 (Proxy vs Native TLS Fingerprints)
- Current rustls stack lacks GREASE ciphers/extensions and only exposes TLS1.3 default suites + a handful of TLS1.2 ECDHE variants, so JA3/JA4 hashes naturally diverge from native Chrome/Firefox outputs.
- HeaderProfileStage still feeds the full catalog from profiles, but planner logs “cipher not supported” and drops everything rustls can’t emit; until I add a TLS backend with GREASE + RSA suites, fingerprint parity is impossible.
- ALPN is clamped to `http/1.1` because HTTP/2 parsing isn’t wired yet, so any site sniffing ALPN will see `h1` even when the profile advertises `h2`.
- `handle_connection` always routes decrypted traffic through the HTTP/1.1 parser and `copy_bidirectional`, so every H2-capable destination is effectively downgraded to HTTP/1.1 despite the browser advertising H2 over the wire.

## Session 40 (Pending HTTP/2 + DNS fixes)
- Client H2 bridge currently emits DATA before HEADERS, triggering `unexpected frame type` resets; fix by sending headers immediately and keeping SendStream alive until body flushes.
- DNS resolution needs retry/cache plus fallback to system resolvers when `WSANO_DATA` surfaces on Windows, otherwise upstream dials fail mid-session.
- Implemented an h2 response helper that chunks DATA via the same `SendStream`, guaranteeing HEADERS go out first and the stream stays alive through body flush.
- Upstream resolver now caches host:port tuples, retries tokio lookups with jitter, and falls back to blocking `getaddrinfo` whenever it sees WSANO_DATA or empty iterator results.
- Globals shim now honors profile-defined `vendor` plus `vendor_flavors` (set the latter to `null` to hide the property entirely) so navigator fingerprints stop leaking the proxy defaults.
- 2fingerprint_spoof_v2.js reintroduces the device spoof section and adds deterministic WebGL parameter overrides; profiles can add `webgl_parameters` to lock BrowserLeaks “Parameters” hashes to lab baselines.

## Session 9 (Initial HTTP/2 Plumbing)
- Client-facing TLS now advertises `h2` + `http/1.1`; branch after the handshake and drive `h2::server` when ALPN selects `h2`, otherwise retain the existing HTTP/1.1 parser path.
- Each HTTP/2 stream becomes its own `Flow`: buffer the request body, run the same stage pipeline, and emit telemetry with both client/upstream protocol labels for observability.
- Upstream legs use rustls+h2 per request; if the origin refuses `h2` reset the stream (no translation to HTTP/1.1 yet), so profile planners enforced to `h2` ALPN for those flows.
- HTTP/1.1 flows still isolate ALPN to `http/1.1` to avoid advertising protocols the data plane cannot honor; planner output is rewritten accordingly before dialing upstream.

## Session 10 (Behavioral Noise Engine Skeleton)
- New `static_proxy/200/` directory holds the behavioral JS shim; assets.rs now embeds it so CSP hashes and injection order stay deterministic.
- `BehavioralNoiseEngine` (Rust side) derives per-flow plans, recognizes envelopes tagged by the JS shim, and appends proxy-side noise placeholders without corrupting opaque telemetry formats.
- `BehavioralNoiseStage` sits right after `HeaderProfileStage`, toggles the engine for each flow, marks metadata, and rewrites request bodies only when the JS layer already wrapped them.
- Flow metadata grew a `behavioral_noise` struct so stages + telemetry can agree on session keys, cadence, and script handles; BodyBuffer gained helpers for replacing payloads safely.

## Session 11 (Behavior Engine Type Fix)
- Windows rustc hit E0283 around `serde_json::Map::entry`; resolve by calling `.entry(String::from("noise"))` in the behavior module so inference picks the intended key type.
- `h2::server::SendResponse::send_reset` returns `()`, so just invoke it and log the outcome; don't pattern-match on a non-existent `Result` when emitting HTTP/2 resets.

## Session 12 (BrowserLeaks TLS Readings)
- If BrowserLeaks shows JA4 with pq-hybrid key shares or RSA suites, the flow bypassed STATIC because `UpstreamClient` (rustls) cannot emit those; re-check proxy settings and static-ca trust before blaming TLS planner.
- BrowserLeaks flags “TLS 1.2 disabled” whenever their TLS1.2-only endpoint needs RSA key exchange; rustls (aws-lc) only exposes ECDHE suites, so our current TLS planner will always fail that probe even though TLS1.2/ECDHE works fine. Need alternative backend if you want RSA coverage.

## Session 13 (Key Share Clamping)
- TLS planner now parses `supported_groups` / `key_share_order` from profiles and feeds them into `TlsClientPlan` so upstream connections share the same key-share order the browser claims.
- `UpstreamClient` installs those groups into `aws_lc_rs::default_provider().kx_groups`, which strips the default X25519MLKEM768 hybrid when the profile only lists classical curves.
- Unsupported groups (ffdhe, secp521r1, etc.) are skipped with a debug log; rustls still emits whatever curves remain, so keep catalogs honest with what aws-lc exposes.

## Session 14 (Chrome Profile Schema v2)
- `profiles/chrome-windows.json` now mirrors the Firefox schema_v2: cipher_catalog + weighted hello_variants with JA3/JA4 lifted from TLS(Sheet1).csv.
- Keep Chrome ALPN limited to `["h2", "http/1.1"]` until the HTTP/3 data plane exists; planner still records the h3 JA4 string for telemetry comparability.
- Chrome variants reuse the same header personality block (sec-ch values, Accept-Language) so HeaderProfileStage can deterministically rewrite request metadata before TLS planning kicks in.

## Session 15 (Edge Profile Schema v2)
- Edge profile now shares the schema_v2 layout; sec-ch hints swap to `Microsoft Edge` branding while still reporting `navigator.vendor = Google Inc.` for parity with Chromium.
- TLS variants reuse Chrome’s cipher catalog/permutations but add the `application_settings` extension in metadata so I can enable ALPS once the data plane understands HTTP/3.
- Edge fallback ALPN stays `h2`/`http/1.1`; planner still clamps to protocols you can terminate today even though the profile documents the richer extension order.

## Session 16 (HTTP/3 Scaffolding Kickoff)
- Added `Http3Config` to `StaticConfig` + example TOML so operators can gate the QUIC stack explicitly; default binds to listener_addr:port+1 but stays disabled.
- ProxyServer now passes the http3 feature flag down to `handle_connection`; placeholder toggles exist before wiring a QUIC listener so I can branch per-flow once QUIC lands.
- Next steps: extend TLS planner to carry ALPS payloads, introduce `proxy::quic` module (quinn) for listener/upstream legs, and teach Flow to host HTTP/3 stream bodies.


## Session 17 (Upstream Boring Toggle)
- `Cargo.toml` exposes `upstream-boring` feature flag plus optional `tokio-boring` dependency so operators can flip to OpenSSL/boring TLS when rustls lacks cipher coverage.
- `UpstreamClient::connect` now dispatches to either rustls or boring backend; keep `upstream_selected_alpn()` helper in sync because SslStream exposes ALPN through `ssl().selected_alpn_protocol()` rather than rustls state.
- Introduce `UpstreamTlsStream` type alias gated by feature so the rest of the proxy (pipeline copying, HTTP/2 forwarder) remains generic regardless of backend choice.
- Connection handlers must pass `http3_enabled` down to `plan_from_profile` once planner learns to drop `h3`/ALPS entries unless QUIC is configured; treat ALPN overrides explicitly to avoid accidentally advertising H3 without data-plane support.
- `finalize_alpn` intentionally takes `Option<&TlsClientPlan>`; whenever you unwrap the plan in client.rs you still need to pass `Some(plan)` so the helper retains override behavior.

## Session 18 (HTTP/3 Execution Plan)
- QUIC support needs a dedicated `proxy::quic` module backed by `quinn` so you can terminate client-side HTTP/3 while keeping HTTP/1.1/H2 paths untouched.
- TLS planner must emit ALPS payloads (or explicitly clear them) and gate H3/H2 ALPNs based on `http3_enabled`; static.example.toml already carries the flag so config plumbing exists.
- Client-side: spin a QUIC listener bound to `Http3Config.listener_addr`; reuse Flow metadata so stages stay agnostic to transport, but record `client_protocol = "h3"` for telemetry.
- Upstream leg requires an HTTP/3 client (quinn + h3 crate) that mirrors the same TLS plan and ALPN selection so origins see a consistent fingerprint.
- Until both legs are wired, keep `http3_enabled = false` in configs; otherwise server will immediately flag the proxy because you advertise h3 without servicing it.



## Session 21 (IPv6 upstream dialing)
- `proxy::client::UpstreamClient` now uses `tokio::net::lookup_host` and iterates resolved IPv4/IPv6 addresses with detailed tracing, removing the IPv4-only string formatting bug.

## Session 22 (Upstream limitations callout)
- Keep these limitations highlighted until pooling + concurrent IPv4/IPv6 dialing land; regressions should be logged in telemetry when implemented.

## Session 23 (Alt-Svc normalization wired)
- `AltSvcStage` now mirrors the Python addon: parses Alt-Svc headers, downgrades any h3/quic advertisement to h2, normalizes risky ports, and supports Remove/Redirect strategies.
- Unit tests cover downgrades and removal; extend coverage once redirect strategy gains production semantics.

## Session 24 (Header profile parity focus)
- Next Rust tasks demand mirroring `header_profile_addon.py` ordering: remove -> replace -> replaceArbitrary -> replaceDynamic -> set -> append to keep Accept negotiation deterministic.
- HeaderProfileStage now parses per-profile JSON into typed rules and mutates Flow.request headers in Python parity order: remove -> replace -> replaceArbitrary -> replaceDynamic -> set -> append.
- ReplaceDynamic inspects path + Accept header (with MIME prefix matching) so Accept spoofing from firefox-windows.json actually applies, and FlowMetadata now tracks the resulting `user_agent` for pipeline + telemetry consumers.
- Flow metadata must keep `profile_name`, `browser_profile`, `user_agent`, and `fingerprint_config` populated exactly like Python for TLS planner.
- CSP + JS stages share nonce/hash state; ensure Flow metadata exposes both so telemetry + behavioral noise modules can read them.
- Plan to extend tests under `tests/unit` mirroring Alt-Svc coverage for header reorder + CSP rewriting once implementation lands.
- Injection timing still uncertain; verify JsInjectionStage runs before CSP-enforced execution deadlines.

## Session 26 (HTTP/1.1 real parsing wired)
- `handle_http1_session` now parses request bytes, runs request stages, dials upstream, buffers the full response, executes response stages, and reserializes mutated headers/bodies back to the client.
- Added `parse_http_response`, chunked decoder, and helpers that normalize `Transfer-Encoding: chunked` into concrete body buffers with updated Content-Length so stages operate on real payloads.
- Upstream proxying no longer uses `proxy_data`; enforce Content-Length after every mutation and stream stage output back through `send_response_to_client`.
- `cargo check` succeeds (warnings only), ensuring the new HTTP plumbing compiles before layering header/CSP/JS parity work.

## Session 27 (HTTP/2 upstream fallback)
- `forward_h2_request_inner` now inspects upstream ALPN; when origins only offer HTTP/1.1, log a downgrade warning and reuse the HTTP/1.1 parser to bridge the stream instead of resetting the client.
- Added `forward_h2_over_h2` and `forward_h2_via_http1` helpers so the H2 server path can fan out to either an h2->h2 tunnel or h2->h1 translation without duplicating serialization logic.
- Fallback reuses `send_request_to_upstream` + `parse_http_response`, enforces Content-Length, and emits the response back to the browser as HTTP/2 frames, keeping telemetry intact.

## Session 28 (HTTP/2 buffering parity)
- HTTP/2 server path now buffers upstream responses into Flow.response, runs StagePipeline response hooks, and only then serializes mutated headers/bodies back through h2 frames.
- `forward_h2_request` and helpers take `StagePipeline` references so fallback + h2->h2 legs share the same response mutation entry point.
- Handle_http2_session only runs request stages prior to dialing; response telemetry still emitted after forward completes successfully.

## Session 29 (HTTP/2 stream concurrency)
- `handle_http2_session` now spawns a task per accepted stream so long-lived requests no longer block subsequent multiplexed streams.
- New `process_http2_stream` helper encapsulates the per-stream pipeline execution, TLS planning, forwarding, and telemetry emission.
- Per-stream tasks clone StagePipeline/Telemetry/TLS metadata, log forwarding errors with host context, and prevent “loading forever” hangs caused by serialized HTTP/2 handling.

## Session 30 (HTTP/2->HTTP/1 fallback hygiene)
- HTTP/1 serialization now always emits `HTTP/1.1` in the request line so fallback connections never send the illegal `HTTP/2.0` verb to legacy origins.
- `forward_h2_via_http1` synthesizes a Host header from SNI/CONNECT metadata when the client (HTTP/2) omitted it, ensuring upstream servers don’t drop the request as malformed.
- These two fixes keep fallback viable against origins that only speak HTTP/1.1 while browsers negotiate HTTP/2 with the proxy.

## Session 36 (Globals shim parity)
- `static_proxy/assets/js/1globals_shim.js` now mirrors the Python addon: navigator/screen/performance proxies resolve against `__STATIC_CONFIG__` and backfill `__static_spoofed_globals` for the bootstrap eval guard.
- Shim must load before config_layer; every getter pulls config lazily so late-arriving JSON works without race conditions.
- Keep DOMException fallbacks in mind: browsers without the constructor still get deterministic errors via Error objects.
- Performance jitter derives from deterministic PRNG seeded by flow/session metadata so replay traces remain stable across eval sandboxes.

## Session 37 (CSP compatibility)
- CspStage no longer forces `'strict-dynamic'` onto every response; only honor it when the origin already set it so that host-based script-src entries keep working.
- Fallback CSP now emits `'script-src 'self' 'unsafe-inline''` (no nonce/hashes) so you never downgrade pages that previously ran without a policy.
- Script hashes are appended only when allowed (no `'unsafe-inline'` present or the origin already supplied its own nonce/hash), so upstream inline bundles keep executing under their original allowances.
- Latest tweak: detect and reuse origin nonces automatically, generating our own only for strict policies that lacked `unsafe-inline`, keeping our injected bundle alive without breaking permissive sites.

## Session 31 (HTTP/2 diagnostics + timeout)
- Instrumented `forward_h2_over_h2` with pseudo-header logging plus 10s timeout around the upstream response future so you can see which requests hang and reset the stream instead of deadlocking the browser.
- HTTP/2 body reader must call `RecvStream::flow_control().release_capacity(len)` for every chunk; otherwise the upstream hits a zero window and the browser hangs waiting forever.

## Session 32 (Header profile rewrites)
- HeaderProfileStage now parses per-profile JSON into typed rules and mutates Flow.request headers in Python parity order: remove -> replace -> replaceArbitrary -> replaceDynamic -> set -> append.
- ReplaceDynamic inspects path + Accept header (with MIME prefix matching) so Accept spoofing from firefox-windows.json actually applies, and FlowMetadata now tracks the resulting `user_agent` for pipeline + telemetry consumers.

### Session 33 (YouTube H2 fallback bug)
- YouTube video hosts frequently negotiate HTTP/1.1 upstream even when the client speaks HTTP/2, triggering our h2->h1 fallback path inside `forward_h2_via_http1`.
- When that happens I currently try to feed HTTP/2 pseudo-headers (`:status`, `:authority`) straight into the h2 response encoder after receiving HTTP/1.1 headers, which surfaces `user error: malformed headers` and resets the stream.
- Need to sanitize pseudo-headers and strip hop-by-hop entries (Connection, Transfer-Encoding) before re-encoding response to the browser, otherwise video segments stall forever.

### Session 34 (HTTP/2 header sanitizer)
- Added `sanitize_response_headers_for_h2` so every h2 response drops hop-by-hop headers, lowercases names, and rebuilds the head via `build_http2_response_head` before `SendResponse` injects `:status`.
- Both the pure h2 path and the h2->h1 fallback now enforce Content-Length, normalize headers, and only then stream bytes to the client—prevents the malformed header resets seen on googlevideo.com segments.

### Session 35 (Inline JS pipeline)
- Hardened the HTTP/1 parser to treat 1xx/204/205/304 as bodyless so googlevideo range requests don’t hang when origins omit Content-Length.
- JsInjectionStage now renders the bootstrap/shim/config/spoofing/behavior scripts, injects them before </head>|</body>, and records sha256 hashes plus nonce-aware script tags.
- CSP stage rewrites Content-Security-Policy headers (or synthesizes one) with `'nonce-...'`, `'strict-dynamic'`, and the JS hashes during a new finalize hook so browsers never kill our inline bundle.

## Session 38 (Fingerprint spoof wiring)
- 2fingerprint_spoof_v2.js must read `__STATIC_CONFIG__` + `__STATIC_SESSION_ID` that HeaderProfileStage/materialized profiles emit; config_layer.js is authoritative for exposing those globals.
- Keep spoof toggles driven by profile config; stripping random spoof blocks without updating configs causes NightmareJS-style bot detection (fingerprint.com evidence).
- JS assets load order stays bootstrap -> globals -> config_layer -> fingerprint spoof; any new dependencies must respect this deterministic chain for CSP hashes.
- NightmareJS detections usually spike when Math noise + aggressive automation evasion collide; lean on profile-driven toggles before ripping out spoofers wholesale.

## Session 39 (NightmareJS fallout)
- Fingerprint bundle must shrink to canvas/audio/WebGL primitives plus shared RNG helpers; migrate navigator/plugins/storage/timezone spoofing into globals shim for consistency.
- Drop math noise + automation denial paths; Nightmare classifiers flag deterministic errors and blanket geolocation failures.
- Bootstrap hooks (eval/Function/DOM guards) need feature gates tied to CSP injection; offsetWidth/Height jitter becomes optional to avoid headless heuristics.
- Introduce `window.__static_rng(seed)` + `window.__static_hash(str)` so future shims share deterministic entropy instead of reimplementing PRNGs.

## Session 41 (DNS cache follow-up)
- Upstream resolver file already imports `once_cell::sync::Lazy`; Cargo.toml must include once_cell dep or builds fail with unresolved crate.
- Tracing warn! macros treat identifiers named `display` as the field formatter helper, so rename local strings (e.g., `err_msg`) before logging `error = %value`.

## Session 42 (Canvas spoof parity)
- JS bundle now expects `fingerprint.canvas_noise` with thresholds/strides/probabilities so canvas jitter matches BrowserLeaks baselines; defaults mirror legacy (20/10 stride, 0.1 probability, ±1 delta).
- Keep `enable_fingerprint_drift` in profiles when deterministic replay is required; disabling sets `__STATIC_SESSION_ID = "static"` so canvas fingerprints stay fixed across reloads.
- When adding new profiles, always copy `canvas_hash` plus `canvas_noise` block; leaving it empty silently falls back to defaults and risks BrowserLeaks hash mismatch.

## Session 44 (Checkbox regression tracking)
- Checkbox inputs currently fail to toggle unless event listeners mirror 404/src/proxy/js/2fingerprint_spoof_v2.js; when porting JS spoof logic, keep focus/blur/active state wiring identical.

## Session 46 (Profile flatten bug)
- JS config helpers must read the fingerprint block (nested under profiles) or vendor/vendor_flavors leak Chrome defaults; update getConfig/config_layer accordingly.

## Session 47 (Document-start JS injection)
- JsInjectionStage now targets the earliest safe insertion point (after `<head>`, otherwise `<body>`, `<html>`, or DOCTYPE) so the boot/globals/config/spoof bundles execute at document_start before origin scripts.
- HTML fallback remains deterministic (inserts at byte 0 when no tags exist) which keeps inline spoofing ahead of any downstream parser mutations.

## Session 48 (Head-only injection + decode)
- JS stage now refuses to inject unless it can splice the bundle directly inside `<head>`; if the tag is missing synthesize `<head>…</head>` immediately after `<html>`/DOCTYPE so inline execution order matches the mitm addon.
- Responses compressed with `gzip`/`deflate`/`br` are transparently decoded (with headers updated) before HTML rewrites so BrowserLeaks finally sees the Firefox persona instead of Chrome defaults.

## Session 49 (Iframe propagation parity)
- Treat `src/proxy/JS/2fingerprint_spoof_v1.js` as the source of truth for iframe hooks until v2 reaches feature parity; every accessible frame must inherit canvas/audio/webgl spoofers plus navigator proxies.
- When editing `static_proxy/assets/js/2fingerprint_spoof_v2.js`, include MutationObservers and `document.createElement` overrides so late-added frames auto-bootstrap with the spoof stack.
- Bootstrap (`0bootstrap.js`) and globals shim (`1globals_shim.js`) should stay in lockstep with the legacy JS versions—copy over iframe propagation helpers and shared RNG/hash exports whenever v1 changes.
- Future static bootstrap changes should live in `0bootstrap_v3.js`; treat `src/proxy/JS/0bootstrap.js` as canonical behavior and only layer STATIC-specific globals (nonce capture, __static_spoofed_globals) on top of that baseline.

## Session 50 (Bootstrap parity enforcement)
- `static_proxy/assets/js/0bootstrap_v3.js` must be a near byte-for-byte port of `src/proxy/JS/0bootstrap.js`, with additions limited to STATIC marks (`__static_bootstrap_active`) and dual spoofed-global lookups.
- Reuse the legacy DOM/eval guards verbatim so iframe propagation, dynamic script interception, and font-metric spoofing stay identical to Python behavior.
- Allow CSP nonce fallback to `window.__STATIC_CSP_NONCE` but do not invent new heuristics; this keeps Rust injector + JS bundle aligned when document.currentScript is absent.
- When propagating into iframes, mirror both `__404_spoofed_globals` and `__static_spoofed_globals` and flip both bootstrap flags so legacy addons can detect activation.

## Session 51 (Globals shim parity)
- `static_proxy/assets/js/1globals_shim.js` must stay in lockstep with `src/proxy/JS/1globals_shim.js`, with the only additions being STATIC markers (`__static_shim_active`) and dual spoofed-global storage (`__static_spoofed_globals` + legacy alias).
- Keep navigator/screen/performance proxies byte-identical so downstream JS stages inherit the same behavior; any new spoof knobs belong in the legacy file first, then get mirrored here.
- Limit STATIC-specific hooks to config plumbing (reading `__STATIC_CONFIG__`, session ids) and marker toggles.

## Session 52 (Fingerprint spoof parity)
- Treat `src/proxy/JS/2fingerprint_spoof_v1.js` as canonical; `static_proxy/assets/js/2fingerprint_spoof_v3.js` must be a direct port with only STATIC-specific plumbing (config sourcing, session ids, telemetry hooks).
- Mitmproxy path is deprecated—do not keep "dual use" toggles or `__404_*` globals inside v3; everything should execute solely under STATIC’s runtime contracts.
- Preserve iframe propagation, MutationObservers, navigator/timing spoof helpers, and noise engines exactly as in v1; any behavioral changes belong upstream in the legacy file before mirroring.

## Session 53 (STATIC-only fingerprint v3)
- `static_proxy/assets/js/2fingerprint_spoof_v3.js` now emits only `__static_*` globals while still mirroring every hook from the Python/mitm version.
- `getConfig()` prioritizes `__STATIC_CONFIG__` fingerprints before falling back to `__fpConfig`, and all session entropy flows through `__STATIC_SESSION_ID` for deterministic drift control.
- Symbol aliases, telemetry logs, and iframe propagation keep the STATIC naming scheme.

## Session 54 (Config layer v3 wiring)
- `static_proxy/assets/js/config_layer_v3.js` mirrors the legacy config plumbing but is STATIC-only, sourcing fingerprints from `__STATIC_CONFIG__` and emitting readiness on `__static_config_ready`.
- Rust asset loader now injects config_layer_v3 between globals and fingerprint bundles.

## Session 55 (HTTP/1 audit note)
- Step 4 confirmed the HTTP/1 pipeline still fully buffers request/response bodies, so chunked uploads remain unsupported and large transfers will pressure memory until I add streaming plumbing.
- Header mirroring now writes raw bytes upstream/downstream, eliminating the UTF-8 coercion bug that previously blanked binary header values during audits.

## Session 56 (HTTP/2 audit note)
- handle_http2_session/process_http2_stream now explain the per-stream tokio spawn model, and request_parts_from_h2 releases flow-control credit for each DATA chunk so clients can keep uploading.
- Fallback path (h2->h1) documents Host/SNI alignment plus header sanitization, still buffer entire request/response bodies; remember this anytime you think HTTP/2 streaming is “done”.

## Session 57 (Pipeline ordering audit)
- HeaderProfileStage now caches `ProfileRecord`s behind Arc, eliminating per-flow JSON clones while still copying the fingerprint config into Flow metadata for JS injection.

## Session 58 (JS asset parity checks)
- Keep `config_layer_v3.js` wiring `__fpConfig` to the fingerprint slice, not the whole parsed profile, otherwise globals shim/regressions leak unintended vendor strings.
- `1globals_shim_v3.js` must never reference undefined markers—last regression was `window[MARK]`, so treat new markers as constants before use.

## Session 59 (reCAPTCHA CSP + JSON anomalies)
- Allowlisting Google domains inside CSP fallback is now mandatory; otherwise reCAPTCHA iframes load but gstatic scripts stay blocked.
- Timeout + `Unexpected token` JSON errors indicate our injected bundles might still tamper with captcha payloads, so cross-check master.js font spoof diffs against `src/proxy/JS/LEGACYmaster.js` before shipping tweaks.
- When debugging captcha stalls, capture both the console trace and HAR so you can see whether gzip/deflate decoding or font-noise writes corrupted Google responses mid-flight.
- Session 60 (IOCP starvation question): Windows async is handled via tokio's IOCP driver, so our TLS termination never queues overlapping reads/writes on raw handles—TcpStream registration plus rustls wrappers manage completion packets.
- Session 61 (captcha JSON errors): Chrome console shows `Unexpected token` junk bytes, meaning gzip/deflate responses stay compressed when recaptcha expects plaintext JSON; inspect HTTP/1 parser/decoder before spoof stack touches payloads.
- Session 62 (bootstrap v4 parity work): JS bootstrap now mirrors spoofed navigator/screen/perf metrics into child frames, reintroduces deterministic font metric shims, injects sentinel scripts even without CSP nonces, and hooks createElementNS/setAttribute/adoptNode/importNode so dynamic script paths stay guarded.

## Session 64 (FP shim delta review)
- Compared 2fingerprint_spoof v3/v4; v4 missing math/WebRTC/storage/gamepad noise because globals shim now owns navigator-level spoofing.
- Prioritize migrating high-entropy vectors only: WebRTC ICE/SDP, SpeechSynthesis voices, event timing jitter, OffscreenCanvas/WebGL2 hooks, audio worklet noise.
- Skip timezone/viewport/device overrides here—bootstrap/globals now ensure those so duplication would desync personas.

## Session 63 (Globals shim hardening)
- 1globals_shim_v4.js now memoizes navigator.plugins/mimeTypes and cross-links enabledPlugin references just like Chromium; keep spoof data in config.plugins/mime_types to drive it.
- Navigator connection/mediaCapabilities/gpu/storage/battery/performance surfaces return deterministic proxies even if the host lacks them; adjust config fields (network_*, media_capabilities.decoding) when personas need custom outputs.
- Viewport + devicePixelRatio overrides now always derive from config.screen_resolution, so leaving those fields unset still rewrites the window dimensions; update profiles instead of relying on host geometry.
- Notification/geolocation denial flows live entirely inside globals shim (Notification.requestPermission, navigator.permissions.query, navigator.geolocation), so fingerprint JS must not assume those APIs remain native.

## Session 66 (Automation evasion fix)
- Restored `applyAutomationEvasion` in 2fingerprint_spoof_v4.js with a scoped automation prop blacklist + descriptor so webdriver markers get deleted again instead of referencing undefined `disableDescriptor`.
- MediaDevices/Gamepad clone helpers now normalize source objects instead of returning null, and stripped the "BROKEN SNIPPET" breadcrumbs so v4 stays STATIC-only; expect deterministic frozen snapshots even when the host omits hardware.
- Bootstrap (0bootstrap_v4.js) now installs an early canvas guard that hooks getImageData/toDataURL/toBlob before any page script runs, routing noise requests through `__static_canvas_noise_handler` with a fallback jitter so BrowserLeaks’ “before DOM load” probes finally see drift even if the main spoof bundle hasn’t landed yet; 2fingerprint_v4 just registers the handler and only rewraps prototypes when the guard is missing.

## Session 65 (fingerprint v4 media/audio expansion)
- 2fingerprint_spoof_v4.js now post-processes mediaDevices.enumerateDevices + navigator.getGamepads with deterministic IDs/labels derived from profile data to stop native hardware leakage.
- SpeechSynthesis voices spoof uses config-driven catalog fallback so BrowserLeaks sees consistent locales without waiting for onvoiceschanged events.
- Event.timeStamp getter now jitters per-flow via RNG while preserving monotonic progression to break timing correlation without breaking input handling.
- Math trig/exp/root functions emit micro-noise bounded to 1e-10 to evade high-resolution entropy probes yet keep JS apps numerically stable.
- navigator.gpu.requestAdapter wrapper aligns adapter.info with globals shim values and returns deterministic stubs when host lacks WebGPU.

## Session 67 (Canvas guard strategy upgrade)
- Bootstrap canvas guard now seeds per-origin RNGs from __STATIC_SESSION_ID + origin, records plan telemetry once per origin, and restores canvas pixels after each privileged call to avoid double-noise artifacts.
- Guard wraps toDataURL/toBlob/transferToImageBitmap plus Offscreen convert/transfer, gating ephemeral jitter per canvas+reason while honoring the config-layer kill switch (`enable_canvas_guard`).
- 2fingerprint_spoof_v4 registers a handler that forwards to `__static_canvas_plan_executor` when available, falling back to legacy injectCanvasNoise only if the guard is disabled or missing.
- Profiles can now drive guard behavior via `fingerprint.canvas_noise.strategy` (mode/stride/delta/alpha/context/ephemeral), and mirror that object onto `window.__static_canvas_strategy` so bootstrap reads persona knobs in real time.
- When guard is active skip redundant prototype rewraps in fingerprint.js/Offscreen hooks; legacy shims only run if bootstrap is disabled, preventing double jitter on BrowserLeaks canvas probes.

## Session 68 (YouTube CSP inline allowance)
- CSP stage now recognizes YouTube/ytimg hosts and force-adds `'unsafe-inline'` so their legacy inline bootstrap survives without killing our nonce/hashes.
- Inline allowance only triggers for suffix-matched hostnames, preserving stricter CSP everywhere else.
- Script hash emission no longer skips when you inject `'unsafe-inline'`, guaranteeing our bundle stays covered even as you relax the directive.

## Session 69 (CSP pass-through mode)
- Stopped minting fresh CSP nonces in rewrite path; Reuse the origin nonce and lean entirely on script hashes when the site doesn’t expose one.
- Fallback CSP still synthesizes a nonce (stored in Flow metadata) but normal flows keep their directives untouched beyond the additional hashes + captcha allowlist.
- This keeps strict policies like YouTube’s `script-src-elem` intact while still letting our injected scripts execute under the original nonce/hashes.

## Session 70 (YouTube CSP passthrough)
- Added a suffix allowlist (youtube.com/ytimg.com/googlevideo.com) where CSP rewrite is skipped entirely; Only capture the nonce and leave the header untouched so their hashed inline modules survive.
- Other hosts still get the captcha allowlist + hash injection; passthrough applies early in `rewrite_headers` before any mutation.
- (Drive CSP hashes): Passthrough hosts now keep their directives but still append STATIC script hashes + reuse origin nonce so Drive/Google Apps can run the spoof stack without CSP violations.
- Follow-up tweak: skip adding hashes when passthrough flows already expose a nonce so accounts.google.com login keeps its native CSP invariants while nonce-less hosts like Drive continue to get SHA tokens.