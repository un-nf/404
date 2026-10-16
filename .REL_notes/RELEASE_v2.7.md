# v2.7 Release Notes

v2.7 is a rewrite of the STATIC injected JavaScript layer, plus the profile schema, build, and CI work that goes with it. The Linux/WSL distro, the control plane, and the eBPF path from v2.6 are not changed.

Changes are on the `js-updates` branch (about 110 files, +13.6k / -4.6k against `main`). Design notes and evidence are in `docs/javascript-overhaul/`. `INDEX.md` is the entry point. `REL-NOTES.md` has the long-form notes and `AUDIT-R01-R22.md` has the review findings.

## Why

The v2.6 runtime kept its config, original function references and nonce somewhere page script could reach. It also trusted native objects to still behave natively after we patched them. The review work (findings C1-C6, R01-R22) showed several ways to observe the real values or tell that a patch was installed. The changes below are the fixes, grouped by finding.

## JavaScript runtime

### C1: private runtime state

- Config, original function references and the nonce now live in private state. Page code can't reach them through globals or the prototype chain.
- Built-ins are captured once, up front, in `core/primordials.js`. Runtime code calls those captured copies, not `Array.prototype.*` or `Promise.prototype.*` at call time, so a page that overrides them later can't intercept our bookkeeping.
- Config is cloned as bounded, frozen, data-only input.
- New `core/descriptors.js` caches original property descriptors, and the cache survives retries.
- `core/native-refs.js`, `core/guard.js`, `core/nonce.js` and `core/toString.js` were reworked around the above.

### C2: genuine interfaces

- Spoofed APIs are now real interfaces with receiver checks and retained descriptors. The old approach of replacing them with plain objects is gone.
- The shared `core/policy.js` and `core/semantics.js` modules decide what gets reported for a given profile.
- Reworked identity modules: `navigator`, `screen`, `performance`, `timezone`, `fonts`, `plugins`.
- Reworked capability modules: `battery`, `network`, `notifications`, `permissions`, `storage`, `media-capabilities`.
- `identity/date-model.js` is new. Covered `Date` local-time reads are consistent with the profile timezone, and `Intl` gets a default zone, DST conversion and a frozen-options facade. Legacy date-string parsing is normalized by default. It can be denied, or opted out to native, with `timezone_legacy_policy`.
- `spoofing/media-devices.js` was rewritten. It fixes device-kind filtering when the kind is absent or zero, labels devices individually, and denies unknown selections.
- Font perturbation no longer depends on the order fonts are queried. Profiles can restrict font queries.
- WebGL parameter queries no longer have the native null/clamp gates in front of them. Brand and lost-context behavior are kept. Parameter metadata moved into `schema/webgl-parameters.json`.
- UA Client Hints:
  - Inherited `then` getters could observe the native x86 value through `getHighEntropyValues`. This was reproduced in Chrome in the window, child frame, and both worker types.
  - UA-CH now validates receivers synchronously and builds only the requested hints from profile data. It never calls the native `getHighEntropyValues`.
  - Unknown inherited hint names are omitted.
  - Details are in `UA-CH-PROMISE-ISOLATION.md`.

### C3: realms

- Same-origin frames get their own realm instead of the marker-only fallback. The marker-path frame skip is removed.
- Workers are bootstrapped from the original URL. Module workers import the bootstrap before application imports. Classic and module worker bundles are separate (`contexts/worker.js`, `contexts/worker-module.js`).
- Worker profiles carry the privacy observations and no private material.
- The HTML scanner handles comments, raw-text elements, templates and foreign content. It uses `html_tokens` in `js.rs`.
- Worker CSP is no longer weakened. See Proxy below.

### C4: lifecycle

- Initialization runs once and only retries what failed.
- Patches record into a synchronous journal (`core/patches.js`). Rollback and realm disposal are separate. Lifetime scopes (`core/lifetimes.js`) free held wrappers and pending results.
- Async installers are rejected.
- Fixed a reentrant-cancel bug in blocked XHRs (saved timers and generation checks after callbacks).
- `core/events.js` adds query/event suppression and weak listener cleanup.

### C5: measurement-driven changes to canvas, audio, WebRTC

- **Canvas** (`spoofing/canvas.js`) works on isolated copies. There is a new opt-in redacted readback mode that doesn't depend on source pixels. Resource budgets, settings snapshots and cleanup were added. The default is still sparse noise. Our own recovery measurements show it can be approximately matched, so it is not unlinkable.
- **Audio** (`spoofing/audio.js`, largely rewritten):
  - Destination metadata is scoped to real destinations.
  - Topology is tracked per receiver.
  - Zero-frequency handling is fixed.
  - Analyser readback is expanded.
  - Worklet payloads are bounded.
- **WebRTC** (`spoofing/webrtc.js`):
  - SDP rewriting is owned by peer, type and generation, so reversals no longer share state.
  - Collisions are rejected.
  - Close, restart and rollback each dispose their own state.
  - History is finite.
  - There is a new `preserve-relay-routing` policy next to mask-all.
- `evasion/automation.js`, `identity/plugins.js` and `spoofing/webgl.js` were slimmed down substantially.
- `behavioral_noise_v1.js` is retired from the runtime. The source is kept. Nothing live depended on it.
- `privacy/beacon-blackhole.js` was rewritten.

### Known limits

- Real codecs, devices, fonts and GPUs are not emulated, and native operations still reveal them.
- Worklet processor globals and cached/blob/data/pre-existing workers are only partly covered.
- Audio changes can change how things sound. The original BrowserLeaks audio comparison is still pending.
- No claim of unlinkability.
- Browser suites were run locally only, in Chrome, Edge and Brave, for the UA-CH fix. See `CHECKLIST.md`.

## Profiles and schema

- New `schema/runtime-profile.schema.json` (about 2.3k lines). Rust and JS both validate profiles against it, with shared fixtures in `tests/fixtures/profile-validation.json`.
- `src/runtime_schema.rs` is new on the Rust side.
- Semantic checks now cover browser/platform/hints consistency, screen/audio/GPU domains, and WoW64 bitness.
- `chrome-windows.json`, `edge-windows.json` and `firefox-windows.json` were expanded to match the schema. `manifest.json` hashes were regenerated. `scripts/update-static-profile-manifest.ps1` was adjusted.
- Profile precedence is unchanged. Automatic persona selection by host family was removed, and a test pins that. There are no per-host exceptions.
- Profile versions here don't certify updated TLS/TCP/HTTP2 templates.

## Proxy (Rust)

- **Advertised storage** (`profile_overrides.rs`). New settings for the quota and usage numbers a page sees. No disk is ever queried.
  - CLI: `--storage-quota`, `--storage-usage`, `--storage-preset lower|standard|higher` (10/50/100 GiB). Sizes take B, KiB, MiB, GiB or TiB.
  - TOML: `pipeline.advertised_storage = { preset, quota, usage }`. See `config/static.example.toml`. CLI overrides config.
  - Usage must not exceed quota. Values above the JS safe-integer range are rejected.
  - The resolved values are logged at startup.
- **JS injection** (`proxy/stages/js.rs`) grew a lot. It now uses the `oxc_parser` 0.100.0 family (pinned) to find worker prologues and tell module syntax from classic. It builds the worker profile, injects once per flow, and reports unavailable instead of altering the source when it skips a worker.
- **CSP** (`proxy/stages/csp.rs`). The nonce rewrite no longer adds `worker-src` or `blob:`. It only adds the nonce to `script-src` and `script-src-elem`. This means worker CSP is no longer loosened. Workers are covered by the bootstrap import path instead.
- **Headers** (`header_profile.rs`). Cached or unknown Client Hints can't restore the host identity.
- `ProfileStore::load_with_overrides` is new. Seeded candidates are preflighted before random selection.
- `build.rs` now watches all schema, build and lock inputs, so schema-only edits rebuild.
- In debug builds only, `STATIC_TEST_DATA_DIR` (absolute path) redirects CA/cache/control state for integration tests. Release binaries ignore it.

## Build, tests, CI

- `build/build.js` verifies the three generated bundles (`runtime`, `worker-classic`, `worker-module`) as a matched set. `esbuild` is pinned exactly and Playwright 1.58.2 is added. `npm test` runs `tests/*.test.cjs`.
- New test files in `src/STATIC_proxy/tests/`:
  - Node source tests: architecture, descriptors, events, installation, privacy, schema, UA-CH, release tools and others.
  - `*.browser.cjs` Playwright fixtures: canvas, audio, WebRTC/TURN, realms, proxy and UA-CH.
- New workflow `.github/workflows/static-javascript-tests.yml` with separate jobs for Rust, browser, live-proxy and effectiveness checks. The effectiveness job turns on a gate that is expected to fail while default noise stays matchable. It is not muted.
- Release scripts:
  - `build-static-release-manifest.mjs` and `build-distro-release-manifest.mjs` stream file hashes, validate their arguments, skip the output file, and reject duplicate artifact basenames.
  - `.gitattributes` was added to keep manifest bytes stable.
- Local results at the last checkpoint: 81 JS tests and 111 Rust library tests pass. The remote CI workflow has not been run yet.

## Upgrade notes

- No change to the control plane, the distro layout, or the eBPF map.
- The `/status` and `/profiles/*` routes behave as in v2.6.
- Existing configs still load. `advertised_storage` is optional.
- Anything that parsed the injected worker CSP and expected `blob:` or `worker-src` should be rechecked.
- `behavioral_noise_v1.js` no longer ships. Don't reference it.
- The desktop app and shipped profiles must be released together. They have to agree on the profile and binary version.

## Summary

- Runtime state and original references are private and captured before page code runs.
- Spoofed APIs are genuine interfaces with receiver checks. UA-CH no longer touches the native high-entropy path.
- Frames and workers get proper bootstrap paths and the CSP is no longer weakened.
- Profiles are schema-validated on both the Rust and JS sides.
- New advertised-storage controls on the CLI and in config.
- New test suite and CI workflow. Remote CI and some browser gates are still open.