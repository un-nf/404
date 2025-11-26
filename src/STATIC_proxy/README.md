# STATIC Proxy
***Synthetic Traffic and TLS Identity Camouflage***

<div align="center">

**A ground-up Rust implementation of a fingerprint-resistant MITM proxy**

[![Rust](https://img.shields.io/badge/rust-1.76%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](../LICENSE)
[![Protocol](https://img.shields.io/badge/protocols-HTTP%2F1.1%20%7C%20HTTP%2F2-green.svg)]()

[Quick Start](../README.md) • [Architecture](#architecture) • [Configuration](#configuration) • [Roadmap](#roadmap)

</div>

---

## Table of Contents

**Core Concepts**

- [Why STATIC Exists](#why-static-exists)
- [Architecture Overview](#architecture)
- [Build & Setup](#build--setup)

<details>
<summary><b>System Components</b></summary>

- [Configuration](#configuration)
- [Control Plane](#control-plane)
- [Data Plane](#data-plane)
  - [Protocol Detection](#protocol-detection)
  - [Flow](#flow-model)
  - [Stage Pipeline](#pipeline)
  - [Upstream Transport](#upstream)

</details>

<details>
<summary><b>TLS & Fingerprinting</b></summary>

- [TLS Subsystem](#tls-subsystem)
- [Profiles](#profiles)
- [Certificate Management](#certificates)

</details>

<details>
<summary><b>Spoofing Stack</b></summary>

- [Embedded Assets & JS](#assets)
- [Behavioral Noise Engine](#behavioral-noise)
- [CSP Interaction](#csp)

</details>

<details>
<summary><b>Operations</b></summary>

- [Telemetry & Tracing](#telemetry)
- [Testing Strategy](#testing)
- [Troubleshooting](#troubleshooting)
- [Current Limitations](#limitations)

</details>

---

## Why STATIC Exists

### Full-Stack Fingerprint Control

**TLS Layer**
- Owns the entire handshake: cipher order, extensions, key shares
- Deterministic profile selection via `rustls`
- JA3/JA4 string generation and validation

**HTTP Layer**
- Native HTTP/1.1 and HTTP/2 protocol parsing
- Header ordering, client hints, Accept negotiation

**JavaScript Layer**
- CSP nonce generation synchronized with injection
- Canvas/WebGL/Audio fingerprint spoofing
- Iframe boundary propagation
- Behavioral noise coordination between Rust and JS

### Deterministic, Profile-Driven

Every aspect of a request derives from a **single JSON profile**:
- TLS configuration (JA3/JA4, cipher order, supported groups, ALPN)
- HTTP headers (ordering, sec-ch values, Accept patterns)
- JavaScript fingerprints (canvas noise, WebGL params, timing jitter)

Uses **UUID v7 + deterministic RNG** to ensure consistency across sessions. Profiles encode real browser behavior, not theoretical constructs.

### Battle-Tested Against Commercial Fingerprinting

Designed to defeat:
- **FingerprintJS** / **DataDome** / **PerimeterX**
- **BrowserLeaks** / **Pixelscan** / **CreepJS**
- **EFF Cover Your Tracks**

Handles edge cases that trip up simpler solutions:
- HTTP/2 pseudo-header validation
- CSP strict-dynamic policies
- Alt-Svc downgrades
- Iframe context propagation

### Async-Native Rust Architecture

- **Tokio-based** concurrency (no thread pools, no blocking IO)
- **Zero-copy buffers** with `BytesMut`
- **Per-flow state isolation** (no global locks in hot path)
- **Structured telemetry** with `tracing` (JSON export ready)

---

## Architecture

### Repository Structure

```
static_proxy/
├── Cargo.toml                      # Dependencies: tokio, rustls, h2, hyper, serde
│
├── assets/js/                      # Embedded fingerprint spoofing scripts
│   ├── 0bootstrap.js                  # Execution control, eval/Function wrapping
│   ├── 1globals_shim.js               # Navigator/screen property interception
│   ├── 2fingerprint_spoof_v2.js       # Canvas, WebGL, audio, font spoofing
│   ├── behavioral_noise.js            # Coordinated timing/interaction patterns
│   └── config_layer.js                # Profile injection into JS context
│
├── config/
│   └── static.example.toml         # Listener, TLS, pipeline, telemetry config
│
├── profiles/                       # JSON profiles (Chrome/Firefox/Edge)
│   ├── chrome_latest.json             # Schema v2: headers, TLS, behavior
│   ├── firefox_latest.json
│   └── safari_latest.json
│
├── src/
│   ├── main.rs                     # CLI entrypoint (clap args, tracing init)
│   ├── app.rs                      # Wires subsystems, spawns listener
│   │
│   ├── proxy/                      # Core proxy logic
│   │   ├── server.rs                  # TCP listener, protocol detection
│   │   ├── connection.rs              # CONNECT handling, TLS termination, HTTP dispatch
│   │   ├── flow.rs                    # Request/response/metadata container
│   │   ├── pipeline.rs                # Stage orchestration trait
│   │   ├── client.rs                  # Upstream dialer (TCP+TLS with profile plans)
│   │   └── stages/                    # HeaderProfile, CSP, JS, AltSvc, Behavioral
│   │
│   ├── tls/                        # TLS subsystem
│   │   ├── cert.rs                    # CA generation, leaf cert cache (DashMap)
│   │   ├── profiles.rs                # TLS planner (JA3/JA4, cipher/group selection)
│   │   ├── fingerprint.rs             # JA3 string computation for telemetry
│   │   └── handshake.rs               # rustls ServerConfig/ClientConfig builders
│   │
│   ├── config/                     # Configuration system
│   │   ├── settings.rs                # StaticConfig struct, TOML deserialization
│   │   └── profiles.rs                # Profile loader with hot reload (notify crate)
│   │
│   ├── behavior/                   # Behavioral noise engine
│   ├── assets.rs                   # Embedded JS files, SHA-256 precomputation
│   ├── telemetry.rs                # Structured logging (JSON mode, tracing spans)
│   └── utils/                      # Error types, logging helpers
│
└── tests/
    ├── unit/tls_tests.rs              # JA3 serialization, cipher filtering
    └── integration/proxy_tests.rs     # End-to-end flow validation
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser -> HTTP CONNECT -> STATIC (127.0.0.1:8080)                  │
└─────────────────────────┬───────────────────────────────────────────┘
                          ▼
              ┌───────────────────────┐
              │  TLS Handshake        │
              │  (rustls + on-demand  │
              │   cert from Provider) │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │  Extract SNI          │
              │  Build Flow Object    │
              │  { id, request,       │
              │    metadata }         │
              └───────────┬───────────┘
                          ▼
          ┌────────────────────────────────┐
          │  StagePipeline.process_request │
          ├────────────────────────────────┤
          │  ├─ HeaderProfileStage         │
          │  │   └─ User-Agent, sec-ch-ua  │
          │  ├─ CspStage                   │
          │  │   └─ Generate nonce         │
          │  ├─ JsStage                    │
          │  │   └─ Inject spoof scripts   │
          │  ├─ AltSvcStage                │
          │  │   └─ Downgrade HTTP/3       │
          │  └─ BehavioralNoiseStage       │
          │      └─ Tag timing patterns    │
          └───────────────┬────────────────┘
                          ▼
            ┌──────────────────────────┐
            │  UpstreamClient::connect │
            │  (with TlsClientPlan)    │
            └────────────┬─────────────┘
                         ▼
           ┌─────────────────────────────┐
           │  Serialize mutated request  │
           │  -> Upstream TLS -> Origin  │
           └─────────────┬───────────────┘
                         ▼
         ┌─────────────────────────────┐
         │  Parse response             │
         │  -> process_response_*      │
         └────────────┬────────────────┘
                      ▼
         ┌─────────────────────────────┐
         │  Serialize mutated response │
         │  -> Browser                 │
         └────────────┬────────────────┘
                      ▼
         ┌─────────────────────────────┐
         │  Telemetry Emission         │
         │  (SNI, JA3, profile,        │
         │   stage mutations)          │
         └─────────────────────────────┘
```

---

### Configuration Sections

#### **Listener**
```toml
[listener]
addr = "127.0.0.1"
port = 8080

[http3]
enabled = false
bind_address = "127.0.0.1"
bind_port = 8081
...
```

#### **TLS**
```toml
[tls]
ca_cert_path = "certs/static-ca.crt"
ca_key_path = "certs/static-ca.key"
cache_dir = "certs/cache"
```

#### **Pipeline**
```toml
[pipeline]
profiles_path = "../profiles"
default_profile = "firefox-windows"
js_debug = false
alt_svc_strategy = "normalize"
```

#### **Telemetry**
```toml
[telemetry]
mode = "stdout"
```

---

## Control Plane

### Application Startup

**Flow**: `main.rs` -> `app.rs` -> subsystem initialization

1. **Parse CLI arguments** (`clap`)
2. **Load & validate configuration**
3. **Initialize `tracing_subscriber`** for structured logging
4. **Spawn `App::run()`**:
   - Profile hot-reload watcher (`notify` crate)
   - Telemetry sink
   - TLS certificate provider
   - TCP listener tasks

### Telemetry Modes

| Mode | Command | Output |
|------|---------|--------|
| **Human-readable** | `cargo run` | Pretty-printed logs to stdout |
| **JSON structured** | `cargo run -- --json-logs` | Serde-encoded events (Loki/ELK ready) |
| **Debug** | `RUST_LOG=static_proxy=debug cargo run` | Per-flow breadcrumbs, JA3, pipeline stages |
| **Trace TLS** | `RUST_LOG=static_proxy::tls=trace cargo run` | Deep TLS handshake diagnostics |

---

## Data Plane

### Protocol Detection

The proxy peeks at incoming TCP connections to determine protocol:

| First Bytes | Protocol | Handler |
|-------------|----------|---------|
| `CONNECT` | HTTP CONNECT tunnel | `handle_connect_tunnel` |
| `0x16` | Direct TLS ClientHello | `accept_tls_session` |
| `GET`/`POST`/etc | HTTP/1.1 request | `handle_http1_session` |

#### CONNECT Handling
1. Parse `CONNECT host:port HTTP/1.1`
2. Validate hostname
3. Respond with `200 Connection Established`
4. Record target in `FlowMetadata.connect_target` for upstream resolution

#### TLS Termination
- Uses `tokio_rustls::TlsAcceptor` with on-demand certificate generation
- Extracts SNI from `ServerConnection::server_name()` (rustls 0.23 API)
- Falls back to `connect_target` when SNI is missing

### Flow Model

A `Flow` represents a complete HTTP exchange:

```rust
pub struct Flow {
    id: Uuid,                         // UUID v7 for deterministic ordering
    request: RequestParts,            // Headers, method, URI, body buffer
    response: Option<ResponseParts>,
    metadata: FlowMetadata,           // Profile, TLS, telemetry state
    behavioral_noise: BehavioralNoiseMetadata,
    fingerprint_config: Value,
    timers: Timers,
    tls_plan: Option<TlsClientPlan>,
}
```

**FlowMetadata** bridges network stack, pipeline, and telemetry:
- TLS SNI and CONNECT target
- Profile names (header + TLS + behavioral)
- CSP nonces and script SHA-256 hashes
- JA3/JA4 strings
- Upstream protocol (HTTP/1.1 vs HTTP/2)
- Stage mutation logs

> **Performance**: Buffers use `BytesMut` for zero-copy mutations during pipeline stages.

### Pipeline

**Execution order** (deterministic, mirrors Python 404 pipeline):

```
1. HeaderProfileStage
   └─ User-Agent, sec-ch-ua, Accept-Language
   └─ Order: remove -> replace -> replaceArbitrary
            -> replaceDynamic -> set -> append

2. AltSvcStage
   └─ Downgrade/strip HTTP/3 advertisements
   └─ Normalize port lists

3. CspStage
   └─ Inject CSP nonces
   └─ Rewrite headers to allow injected JS

4. JsInjectionStage
   └─ Embed bootstrap + shim + config + spoof
   └─ Record SHA-256 hashes

5. BehavioralNoiseStage
   └─ Tag flow with noise plan
   └─ Coordinate with JS timing patterns
```

Each stage implements async hooks:
- `process_request`
- `process_response_headers`
- `process_response_body`
- `on_complete`

### Upstream

**Connection flow** (`proxy::client::UpstreamClient::connect`):

1. **Resolve hostname** via `tokio::net::lookup_host` (IPv4/IPv6)
2. **Dial TCP** with `TcpStream::connect`
3. **Build `rustls::ClientConfig`** from TLS plan:
   - Cipher suite ordering
   - Supported groups (X25519, secp256r1, etc.)
   - Key-share order
   - ALPN preferences (`h2`, `http/1.1`)
4. **Execute TLS handshake** -> `tokio_rustls::client::TlsStream<TcpStream>`
5. **Serialize request** -> `send_request_to_upstream()`
6. **Bidirectional copy** -> `proxy_data()`

> **Future**: Toggle to `tokio_boring::SslStream` for RSA/PQ cipher support via `upstream-boring` feature.

### HTTP/1.1 Engine

**Flow** (`connection.rs::handle_http1_session`):

```md
parse_http_request (chunked decoder normalizes to contiguous buffer)
         ... *then*
Stage pipeline mutates request
         ... *then*
Upstream connect/dial
         ... *then*
send_request_to_upstream()
         ... *then*
parse_http_response (buffer complete response)
         ... *then*
Stage pipeline mutates response
         ... *then*
send_response_to_client()
```

**Edge cases handled**:

- Bodyless codes (1xx/204/205/304) to avoid Content-Length hangs
- Chunked encoding normalization

> TODO: Streaming bodies for large payloads

### HTTP/2 Engine

**Flow** (`connection.rs::handle_http2_session`):

- Leverages `h2::server` for client-side HTTP/2 with ALPN `h2`
- Each incoming stream spawns `process_http2_stream()` for per-request state isolation

**Upstream branching**:
- **`forward_h2_over_h2()`**: When origin negotiates H2
- **`forward_h2_via_http1()`**: Fallback when upstream ALPN lacks H2

**Response handling**:
- Buffers complete headers/body before running response stages
- `sanitize_response_headers_for_h2()` removes hop-by-hop headers
- Enforces Content-Length, normalizes lowercase names

**Flow control**:
- `RecvStream::flow_control().release_capacity()` per chunk
- Prevents zero-window deadlocks
- 10s timeout guard prevents hung upstream from blocking client

### HTTP/3 Roadmap

> `Http3Config` already part of `StaticConfig`. 

- [ ] `proxy::quic` module built on `quinn`
- [ ] CONNECT-UDP handler
- [ ] ALPS serialization within TLS planner
- [ ] Telemetry labels for H3 flows

---

## TLS Subsystem

### Certificate Provider

**`tls::cert::TlsProvider`** bootstraps CA:

1. **On first run**: Generate CA via `rcgen` (with `pem` feature)
2. **Write** `certs/static-ca.{crt,key}` to disk
3. **Leaf cache**: `DashMap<String, CachedCert>` keyed by lowercase SNI
   - Entries store `Arc<CertifiedKey>` + `Instant` timestamp
   - **TTL**: 24 hours (lazy invalidation on lookup)
4. **`ResolvesServerCert`** impl returns cached cert or generates new leaf signed by CA
   - Chain: `[leaf, ca]`
   - Missing SNI falls back to `static.local`

### TLS Planner

**`tls::profiles.rs`** reads schema_v2 TLS blocks from profile JSON:

**Profile fields**:
- `cipher_catalog`: Canonical cipher sets
- `hello_variants`: Weighted variants with JA3/JA4 strings
- `supported_groups`: X25519, secp256r1, etc.
- `key_share_order`: Client key share priority
- `alpn`: Protocol preferences
- `padding`/`padding_seed`: Extension padding

**Planning flow**:
```rust
plan_from_profile() 
    -> Select variant (deterministic RNG seeded from Flow.id)
    -> Filter unsupported ciphers/groups based on rustls backend
    -> Construct TlsClientPlan
    -> Consumed by UpstreamClient::connect
```

### JA3/JA4 Fingerprinting

**`tls::fingerprint.rs`** recomputes JA3/JA4 strings from emitted TLS plan for telemetry validation.

**Comparison against BrowserLeaks**:
- Direct fingerprint validation
- Cipher coverage tracking
- Extension order verification

### Handshake Helpers

**`tls::handshake.rs`** provides utilities:

```rust
ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_cert_resolver(resolver)
    
config.alpn_protocols = vec![b"h2", b"http/1.1"]  // Until HTTP/3 lands
```

---

## Profiles

### Profile Structure

Profiles located in `static_proxy/profiles/*.json` (Chrome/Edge/Firefox).

**Schema v2 fields**:

#### **Metadata**
```json
{
  "metadata": {
    "profile_name": "firefox-windows",
    "description": "Firefox 120+ on Windows 11",
    "browser_family": "firefox",
    "viewport": {"width": 1920, "height": 1080},
    "resolution": {"width": 1920, "height": 1080}
  }
}
```

#### **Headers**
```json
{
  "headers": {
    "remove": ["X-Forwarded-For"],
    "replace": {"User-Agent": "Mozilla/5.0..."},
    "set": {"sec-ch-ua": "\"Firefox\";v=\"120\""},
    "append": {"Accept-Language": "en-US,en;q=0.9"}
  }
}
```

#### **TLS**
```json
{
  "tls": {
    "schema_version": 2,
    "cipher_catalog": {
      "TLS_AES_128_GCM_SHA256": {...},
      "TLS_CHACHA20_POLY1305_SHA256": {...}
    },
    "hello_variants": [
      {
        "weight": 0.8,
        "ja3": "771,4865-4866-4867...",
        "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "extension_sequence": [...],
        "alpn": ["h2", "http/1.1"],
        "supported_groups": ["x25519", "secp256r1"]
      }
    ]
  }
}
```

#### **Behavior**
```json
{
  "behavior": {
    "fingerprint_spoof": true,
    "behavioral_noise": false,
    "canvas_noise": {
      "enabled": true,
      "threshold": 20,
      "stride": 10
    },
    "automation_evasion": true,
    "geolocation_override": false
  }
}
```

### Profile Loading

**`config/profiles.rs`** implements hot-reload:

1. **Watch directory** via `notify::RecommendedWatcher`
2. **Parse JSON** into typed structs
3. **Update `Arc<ProfilesStore>`** consumed by stages + TLS planner
4. **On parse failure**: Last good config remains active
5. **Telemetry**: Warnings with file path on errors

---

## Assets

### Embedded JavaScript

**`assets.rs`** uses `include_str!` to embed JS files and `sha2` for SHA-256 digests at compile time.

**`AssetCatalog`** exposes:
- `content`: Raw JavaScript
- `sha256`: Precomputed hash
- `nonce`: Per-flow generated nonce

### Load Order (CSP determinism requirement)

```
1. assets/js/0bootstrap.js
   └─ Sandbox guard, ensures single injection

2. assets/js/1globals_shim.js
   └─ navigator/window proxies

3. assets/js/config_layer.js
   └─ Writes __STATIC_CONFIG__, passes profile JSON to JS

4. assets/js/2fingerprint_spoof_v2.js
   └─ Canvas/WebGL/Audio/Font spoofing
   └─ Automation evasion + geolocation logic

5. assets/js/behavioral_noise.js
   └─ Coordinates with Rust BehavioralNoiseEngine
```

### CSP Integration

**`CspStage`** uses asset hashes and per-flow nonce to rewrite `Content-Security-Policy` headers:

- Adds `'strict-dynamic'` only when upstream policy allows
- Hashes inline JS from origins to avoid breakage
- Appends STATIC script hashes
- Reuses origin nonces when available

**Injection point**: Near `</head>` or `</body>` (deterministic fallback to synthesize `<head>` if missing)

---

## Behavioral Noise

### Rust Side

**`behavior/`** holds `BehavioralNoiseEngine`:

- Parses profile-provided noise strategies
- Cadence, payload templates, envelope structure
- Stage toggles engine per flow
- Writes metadata consumed by JS

### JavaScript Side

**`behavioral_noise.js`** receives instructions via `__STATIC_CONFIG__`:

- Annotates outgoing requests
- Modifies DOM changes
- Signals back to Rust through HTTP metadata envelopes

### Flow Metadata

Tracks:
- `behavioral_noise.enabled`
- `plan_id`
- `session_key`
- Enables telemetry correlation

---

## Telemetry

### TelemetrySink

**`telemetry.rs`** defines structured emission:

**Methods**:
- `flow_start`
- `flow_stage_breadcrumb`
- `flow_error`
- `flow_complete`

**Emitted fields**:
- Flow ID, profile key
- TLS SNI, CONNECT target
- JA3/JA4 strings
- TLS variant name
- Header stage actions
- Alt-Svc rewrites
- CSP injection stats
- Upstream protocol
- Duration

### Logging Backend

**`tracing_subscriber`** configured via `app.rs`:

- Hooks `RUST_LOG` environment variable
- **JSON mode**: Serde objects for observability pipelines
- **Human mode**: Pretty-printed for development

### Future Metrics

- Certificate cache hit/miss counters
- Upstream latency histograms
- HTTP/2 stream concurrency metrics

---

## Certificates

### CA Management

**Generated files** (`certs/`):
- `static-ca.crt`: Public certificate (distribute to browsers)
- `static-ca.key`: Private key (protect via OS-level ACLs)

**Security recommendations**:
- Password-protected PFX imported to OS store
- DPAPI/TPM wrapping for key material
- Offline root + online intermediate hierarchy

### Leaf Cache

**Storage**: `certs/cache/*.der`

**TTL enforcement**:
- 24 hours (runtime validation)
- No background eviction yet
- Future: Async task for proactive cleanup

**Tracing**: Cache hits/misses and regeneration events logged

---

## Testing

### Unit Tests

**`tests/unit/tls_tests.rs`**:
- JA3 serialization validation
- Cipher filtering logic
- Key-share ordering

**Coverage needed**:
- TLS planner translation
- Unsupported cipher handling
- Profile schema validation

### Integration Tests

**`tests/integration/proxy_tests.rs`**:
- Binary boots with sample config
- TCP listener accepts connections

**Roadmap**:
- End-to-end test harness with headless browser
- Import static CA
- Verify header rewrites
- Validate Alt-Svc downgrades
- Confirm JS injection

### Manual Validation

**BrowserLeaks test suite**:
- TLS fingerprints (JA3/JA4 comparison)
- Canvas hashes
- WebGL parameters
- Font fingerprints

**Debugging**:
- HTTP/2 fallback via tracing logs
- Pseudo-header dumps
- Flow control diagnostics

---

## Limitations

### TLS Coverage

**Missing from rustls/aws-lc**:
- RSA key exchange
- GREASE ciphers/extensions
- Post-quantum hybrid key shares

**Workaround**: `upstream-boring` flag enables `tokio-boring`. Or custom TLS backend in the future.

**Impact**: JA3 limited to ECDHE suites until BoringSSL integration

### HTTP/3

**Status**: Config + roadmap exist, but no QUIC listener yet

**Current**: Planner clamps ALPN to `['h2','http/1.1']`

### Streaming Bodies

**HTTP/1 engine** buffers entire request/response

**Impact**: Large uploads/downloads may pressure memory

**Future**: Streaming pipeline with chunked rewriter and stage API adjustments

### Connection Pooling

**Current behavior**:
- Upstream dials fresh TCP/TLS per request
- No keepalive/pooling
- No configurable timeouts

### DNS Caching

**Minimal caching** implemented

**Windows workaround**: Fallback to blocking `getaddrinfo` when `WSANO_DATA` occurs

**Future**: Happy Eyeballs
---

## Roadmap

### Near-Term (Next 3 Months)

- [ ] **Connection pooling** with keepalive
- [ ] **Configurable timeouts** for upstream dials
- [ ] **Streaming body support** for HTTP/1.1
- [ ] **Unit test coverage** for pipeline stages
- [ ] **Metrics export** (Prometheus format)

### Mid-Term (3-6 Months)

- [ ] **HTTP/3 support** via `quinn`
- [ ] **BoringSSL integration** (`upstream-boring` feature)
- [ ] **ALPS serialization** for TLS 1.3
- [ ] **Happy Eyeballs** DNS resolution
- [ ] **Integration test harness** with headless browser

### Long-Term (6+ Months)

- [ ] **Certificate rotation** automation
- [ ] **TPM key storage** for CA
- [ ] **Remote attestation** capabilities
- [ ] **Performance benchmarking** suite
- [ ] **Documentation site** with examples

---

## Troubleshooting

### Common Issues

#### **Build fails with "Missing dependency: cmake"**

```bash
# Install CMake + NASM
$ choco install cmake nasm  # Windows (Chocolatey)
$ brew install cmake nasm   # macOS (Homebrew)
$ sudo apt install cmake nasm  # Linux (apt)

# Or enable ring backend (dev builds only)
$ cargo build --features rustls/ring
```

#### **Browser shows "NET::ERR_CERT_AUTHORITY_INVALID"**

1. Check CA certificate is imported: Settings -> Certificates -> Authorities
2. Verify `certs/static-ca.crt` exists and matches browser import
3. Restart browser after certificate import

#### **Proxy connects but pages hang**

1. Check upstream resolution: `RUST_LOG=static_proxy::proxy::client=debug cargo run`
2. Verify DNS resolution: Test with known-good domains first
3. Check firewall rules: Ensure outbound HTTPS (443) is allowed

#### **TLS handshake failures**

```bash
# Enable TLS tracing
$ RUST_LOG=static_proxy::tls=trace cargo run

# Look for:
# - "no cipher suites in common"
# - "peer closed connection without sending TLS close_notify"
# - "certificate signature verification failed"
```

#### **HTTP/2 streams reset**

```bash
# Enable H2 diagnostics
$ RUST_LOG=static_proxy::proxy::connection=debug,h2=debug cargo run

# Common causes:
# - Pseudo-header validation errors
# - Flow control window exhaustion
# - Upstream protocol mismatch
```

### Debug Workflow

1. **Start with minimal config**: Use `static.example.toml` as baseline
2. **Enable targeted logging**: Don't use `RUST_LOG=trace` (too noisy)
3. **Test with curl first**: Isolate browser-specific issues
4. **Check telemetry output**: Flow IDs let you correlate requests
5. **Compare against BrowserLeaks**: Validates fingerprint accuracy

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/404/issues)
- **Discussions**: [GitHub Discussions](https://github.com/404/discussions)
- **Telemetry**: Always include `RUST_LOG=debug` output when reporting issues

---

<div align="center">

*For educational and research purposes only. Use responsibly.*

</div>