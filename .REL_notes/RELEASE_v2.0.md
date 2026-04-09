# Release Note: v2.0

## Summary

Lots of changes in this update.
- API Endpoints
- CI Pipeline
- wreq / rustls

This is primarily a developer-facing architecture change. The goal is to make component boundaries more explicit, move release delivery onto a cleaner GitHub path, and document the outbound transport behavior more clearly.

## What Changed

### HTTP control API added to STATIC

STATIC now exposes a localhost control surface on `127.0.0.1`.

Current endpoints:

- `GET /status` for process health and readiness
- `GET /ca/status` for CA certificate presence/status
- `POST /ca/init` for CA material initialization
- `POST /stop` for graceful shutdown
- `GET /telemetry/snapshot` for polled telemetry state
- `POST /profiles/validate` for profile validation warnings

*These are the current localhost control endpoints in this release.*

### Outbound transport moved from rustls to wreq

This release line reflects the completed outbound transport migration away from the old custom rustls-based upstream client path.

What changed in the runtime:

- Outbound origin requests now route through `WreqOriginFetcher` instead of the deprecated rustls `UpstreamClient` path.
- Outbound HTTP connection handling is now delegated to the external `wreq` client stack rather than a custom in-repo upstream HTTP client/pooling implementation.
- `rustls` remains in use for inbound MITM responsibilities only: client-facing TLS termination and on-demand certificate issuance.
- TLS profile translation now feeds a wreq-oriented transport plan instead of a rustls client config builder.
- HTTP/1.1 and HTTP/2 upstream fetches now share the same `OriginFetcher` path.

Profile and transport effects:

- `tls/profiles.rs` now materializes a transport plan for wreq, including ALPN, TLS version bounds, cipher ordering, supported groups, key share ordering, signature algorithms, GREASE flags, record size limits, delegated credentials, TLS extension descriptors, and HTTP/2 settings.
- The shipped browser profiles now drive outbound HTTP/2 behavior through the live `tls.http2` mapping path, including pseudo-header ordering, settings ordering, `enable_connect_protocol`, RFC 7540 priority behavior, flow-control fields, and several reset/buffer settings exposed by `wreq` 6.
- TLS extension handling is more complete than in the initial migration: the runtime now preserves extension codes in the transport plan, applies explicit extension permutation where supported, and can model the old vs new `application_settings`/ALPS codepoint choice from the profile data.
- TLS 1.3 cipher suite ordering is now explicitly preserved in the outbound builder path.
- Profile validation was tightened so unsupported or wire-sensitive claims can be surfaced as warnings during profile load rather than silently claiming support the runtime does not provide.

Important implementation boundary:

- Exact wire behavior is still not guaranteed for every TLS profile field. The runtime now preserves extension codes and applies explicit permutation data, but extensions that cannot be mapped through the current adapter are omitted from the explicit permutation set.
- Some behavior is still library-defined rather than profile-defined. For example, `tls.http2.adaptive_window=true` overrides explicit initial window settings in the current `wreq` path.
- This release adds a more complete transport implementation, not a guarantee that every profile field will match packet captures under every target.

Build and packaging notes:

- GitHub release builds are produced by `.github/workflows/static-release.yml` for Windows, Linux, and macOS targets.
- The Windows release job installs `strawberryperl`, `ninja`, and `llvm`, and exports `LIBCLANG_PATH=C:\Program Files\LLVM\bin` for bindgen-backed native dependencies.
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

- packet-capture validation for every shipped TLS profile permutation
- exact extension-order control for every TLS profile field when the underlying adapter cannot express a given extension