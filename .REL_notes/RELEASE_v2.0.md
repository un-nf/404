# Release Note: v2.0

## Summary

Lots of changes in this update.
- API Endpoints
- CI Pipeline
- wreq / rustls

This is primarily a developer-facing architecture change. The goal is to make component boundaries more explicit and encourage development with STATIC.

## What Changed

### HTTP control API added to STATIC

STATIC now exposes a localhost control surface.

Current endpoints:

- `GET /status` for process health and readiness
- `GET /ca/status` for CA certificate presence/status
- `POST /ca/init` for CA material initialization
- `POST /stop` for graceful shutdown
- `GET /telemetry/snapshot` for polled telemetry state
- `POST /profiles/validate` for profile validation warnings

*These are all current localhost control endpoints in this release.*

### Outbound transport moved from rustls to wreq

This release line also reflects the completed outbound transport migration away from the old rustls-based upstream client path.

What changed in the runtime:

- Outbound origin requests now route through `WreqOriginFetcher` instead of the deprecated rustls `UpstreamClient` path.
- Outbound HTTP connection handling is now delegated to the external `wreq` client stack rather than a custom in-repo upstream HTTP client/pooling implementation.
- `rustls` remains in use for inbound MITM responsibilities only: client-facing TLS termination and on-demand certificate issuance.
- TLS profile translation now feeds a wreq-oriented transport plan instead of a rustls client config builder.
- HTTP/1.1 and HTTP/2 upstream fetches now share the same `OriginFetcher` path.

Profile and transport effects:

- `tls/profiles.rs` now parses a richer transport plan for wreq, including ALPN, TLS version bounds, cipher ordering, supported groups, key share ordering, signature algorithms, GREASE flags, record size limits, and optional HTTP/2 settings.
- The shipped browser profiles now drive outbound HTTP/2 settings through the live `tls.http2` mapping path instead of the older rustls assumptions.
- Profile validation was tightened so descriptive-only or unsupported transport claims can be surfaced as warnings during profile load rather than silently over-promising exact wire fidelity.

Important implementation boundary:

- Exact extension ordering is still not fully controllable through wreq 5.3; the runtime can control extension permutation behavior and several handshake features, but not arbitrary extension-by-type ordering.
- Some HTTP/2 knobs remain schema-level metadata only because *wreq does not currently expose them*.

Build and packaging notes:

- Windows builds for the wreq path currently rely on `boring-sys2`, which in turn requires Git on `PATH` during native build steps.
- The current Windows toolchain also expects LLVM `libclang`; the repo carries `.cargo/config.toml` with `LIBCLANG_PATH` pointing at `C:\Program Files\LLVM\bin` for bindgen.
- These are build-time requirements for producing the STATIC binary.

## GitHub Delivery

Canonical GitHub delivery path @ `un-nf/404`.

- Managed profiles are sourced from `src/STATIC_proxy/profiles/manifest.json`.
- Prebuilt STATIC binaries are sourced from the latest GitHub release.

The desktop updater currently expects these release asset names:

- `static_proxy-windows-x86_64.exe`
- `static_proxy-linux-x86_64`
- `static_proxy-macos-x86_64`
- `static_proxy-macos-aarch64`

For profile updates, fetch `https://raw.githubusercontent.com/un-nf/404/main/src/STATIC_proxy/profiles/manifest.json`, then download each listed profile from `raw.githubusercontent.com` and verify the manifest SHA-256 before installing it into the runtime profiles directory. Any managed profile change therefore needs a matching `manifest.json` update in the same commit.

For binary updates, fetch `https://api.github.com/repos/un-nf/404/releases/latest`, then download the matching platform asset into the app-owned runtime bin directory.

## Scope of This Release

Not included:

- exact extension-order control for every TLS profile field