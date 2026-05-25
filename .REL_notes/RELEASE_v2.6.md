# v2.6 Release Notes

## What Changed

### Windows WSL distro release path

`404_REL` contains a WSL distro and release pipeline.

This release adds:

- Updated documentation - [docs.404privacy.com](https://docs.404privacy.com)
- New `distro/` packaging tree with an Alpine-based rootfs
- `distro/build.sh` for local tarball assembly
- `distro/rootfs/etc/wsl.conf` boot configuration that launches `/opt/404/404-init.sh`
- `distro/rootfs/opt/404/404-init.sh` to attach the packet mutator and start STATIC from the Windows-authored `static.runtime.toml` config
- `.github/workflows/distro-release.yml` to build a musl STATIC binary, compile `ttl_editor.o`, package `404-distro.tar.gz`, sign the manifest, and publish release artifacts

This also formalizes the Linux-side bootstrap contract that the Windows desktop wrapper expects:

- the distro is registered as `404`
- bootstrap runs through `/opt/404/404-init.sh`
- the Windows username is handed off through `/opt/404/win-user`
- the control token is handed off through `/opt/404/control-token`
- STATIC loads its config from the mounted Windows filesystem rather than from an in-distro config copy

### API Updates

```
GET /distro/manifest.json
GET /distro/manifest.json.sig
GET /distro/<tag>/404-distro.tar.gz
```

`404_REL` manages the release artifact shape that the Windows desktop/backend consumes.

### Signed distro manifest and publication verification

The new distro release path includes a dedicated manifest generator and a post-release verification script.

Added tooling:

- `.github/scripts/build-distro-release-manifest.mjs`
- `scripts/verify-distro-publication.sh`

The manifest records:

- `version`
- `sha256`
- `artifact_path`
- `published_at`

### Operator bundles for Windows and macOS

New bundle outputs now include:

- `404-windows-x64.zip`
- `404-macos-aarch64.zip`
- `404-macos-x64.zip`

The Windows bundle contains:

- `404-distro.tar.gz`
- Signed distro manifest files
- Prebuilt `static.runtime.toml`
- Shipped profile catalog
- Control-token location under the expected app-local WSL path

The macOS bundles contains a `404-runtime/` directory with:

- `static_proxy`
- Release manifest files
- Bundled profiles
- Example config

### Authenticated control plane and CA PEM bridge

STATIC's localhost control plane is configurable and can require an application-layer token when `control.token_path` is set.

Config and control-plane changes include:

- New `control` config surface exported from `settings.rs`
- Configurable `control.bind_address`
- Pptional `control.token_path`
- Control-plane request authentication through `X-404-Control-Token`

The token gate covers the existing lifecycle, CA, telemetry, and profile-management routes, including:

- `/status`
- `/ca/status`
- `/ca/init`
- `/stop`
- `/telemetry/snapshot`
- `/profiles/catalog`
- `/profiles/active`
- `/profiles/select`
- `/profiles/validate`

CA responses were also extended so `/ca/status` and `/ca/init` can return `cert_pem` directly. That makes host-side trust installation possible without assuming the caller can read Linux-local certificate paths.

The practical result is that STATIC is now usable as a supervised local service, not only as a standalone localhost proxy.

### eBPF packet-profile integration

The Linux packet mutator is tied to the active browser profile.

`src/ebpf/ttl_editor.c` adds:

- `fingerprint_profile` struct
- `fingerprint_profiles` BPF array map
- Map-backed lookup with fallback defaults when no userspace value is present
- Explicit SYN option rewrite support for MSS, window scale, and timestamp shaping
- Helper paths for IPv4 checksum-safe field updates and header resizing

`STATIC` includes a userspace packet-profile sync path:

- `src/STATIC_proxy/src/ebpf.rs` derives a `PacketProfile` from the active materialized browser profile JSON
- the active packet profile is written into the pinned BPF map at `/sys/fs/bpf/404/fingerprint_profiles`
- startup sync happens when the shared profile store is initialized
- profile changes through `/profiles/select` trigger another sync into the pinned map

The distro bootstrap mounts `bpffs`, attaches `ttl_editor.o`, and pins the `fingerprint_profiles` map so the userspace STATIC process can update it after boot.

Shipped Windows browser profiles carry explicit `packet_profile` blocks and seeded packet overlays. The selected browser persona can carry profile-specific values for TTL, TOS, TCP windowing, SYN option ordering, and limited restart-to-restart device-like variation while preserving the broader Windows packet shape.

---

## Summary

`v2.6` is a distribution and operator-contract release:

- WSL distro path is now packaged in-repo
- Release assets are optimized for ease-of-use on Windows and macOS
- Control plane is now configurable and token-gated
- Host-side trust installation can consume CA PEM data without reading Linux-local files
- Linux packet shaping is now connected to the selected profile through a pinned BPF map and userspace sync path