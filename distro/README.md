# WSL Distro Build And Release

## What lives here

- local packaging script that assembles a WSL-importable Alpine rootfs tarball
- release workflow that builds the musl STATIC binary, compiles the eBPF object, packages the distro, signs the manifest, and publishes to the public update origin
- stable manifest contract

Files:
- `build.sh`: packages the WSL distro tarball from prebuilt artifacts
- `Dockerfile.build`: pinned Alpine 3.19 filesystem used for the exported rootfs
- `rootfs/etc/wsl.conf`: WSL boot configuration that starts `/opt/404/404-init.sh`
- `rootfs/etc/resolv.conf`: fallback DNS config baked into the rootfs
- `rootfs/opt/404/404-init.sh`: Linux-side startup entrypoint inside the distro

## Current Status

- CI explicitly builds `static_proxy` for `x86_64-unknown-linux-musl`
- CI compiles `src/ebpf/ttl_editor.o` separately with clang targeting BPF
- CI packages `dist/404-distro.tar.gz`
- CI generates and signs `dist/distro/manifest.json`
- tagged releases upload the stable manifest to `distro/manifest.json`
- tagged releases upload the immutable tarball to `distro/<tag>/404-distro.tar.gz`
- desktop app derives and embeds the matching `APP_DISTRO_PUBKEY` from the same signing key in its own release workflow

## Rose kernel

The desktop app fetches a stable distro manifest from:

```text
${APP_UPDATE_PUBLIC_BASE_URL}/distro/manifest.json
```

That stable manifest now points at a versioned immutable tarball path such as:

```text
/distro/v1.2.3/404-distro.tar.gz
```

The manifest shape emitted by `.github/scripts/build-distro-release-manifest.mjs` is:

```json
{
  "version": "v1.2.3",
  "sha256": "<hex>",
  "artifact_path": "/distro/v1.2.3/404-distro.tar.gz",
  "published_at": "2026-05-06T00:00:00.000Z"
}
```

The desktop app verifies:

- the manifest signature using `APP_DISTRO_PUBKEY`
- the tarball SHA-256 using the signed manifest contents

## Local Build Inputs

`build.sh` expects two prebuilt inputs:

- a Linux `x86_64-unknown-linux-musl` STATIC binary
- a compiled `ttl_editor.o` eBPF object

Default expected paths:

- `src/STATIC_proxy/target/x86_64-unknown-linux-musl/release/static_proxy`
- `src/ebpf/ttl_editor.o`

Notes:

- STATIC binary must be musl
- Alpine will not reliably run a glibc-targeted `target/release/static_proxy`
- The workflow and the build docs now intentionally point at `target/x86_64-unknown-linux-musl/release/static_proxy`

## Local Packaging CLI

`build.sh` is the local packaging entrypoint.

Usage:

```sh
./distro/build.sh [options]
```

Options:

- `--static-binary PATH`: path to the Linux musl STATIC binary
- `--ttl-object PATH`: path to the compiled `ttl_editor.o`
- `--version VALUE`: version string written into `/opt/404/distro-version`
- `--output PATH`: output tarball path
- `--image-tag VALUE`: temporary Docker image tag used during packaging
- `--help`: print usage

Examples:

```sh
./distro/build.sh
```

```sh
./distro/build.sh \
  --static-binary /abs/path/to/static_proxy \
  --ttl-object /abs/path/to/ttl_editor.o \
  --version v0.1.0-dev \
  --output /abs/path/to/404-distro.tar.gz
```

Build prerequisites:

- `docker` must be installed and available on `PATH`
- the two input artifacts must already exist

Output:

- `dist/404-distro.tar.gz`

The script copies the rootfs into a temporary Docker build context, stages the binary and eBPF object, writes `/opt/404/distro-version`, builds the temporary image, then runs:

- `docker create`
- `docker export`

## eBPF Build CLI

The eBPF object is compiled separately from the distro packaging step.

The Makefile in `src/ebpf` builds:

- `ttl_editor.o`

using:

- `clang -target bpf`
- `llvm-strip`

The current Makefile checks for:

- `clang`
- `llvm-strip`
- `tc`
- `/usr/include/bpf/bpf_helpers.h`
- `/usr/include/linux/bpf.h`

Typical local invocation:

```sh
make -C src/ebpf clean all
```

This object is architecture-independent BPF bytecode, but it still needs a Linux build environment with the expected headers and tooling.

## Rootfs Contents And Boot Behavior

The distro is currently built from Alpine:

- `Dockerfile.build` starts from `alpine:3.19`
- it installs `iproute2` and `libgcc`
- it copies in the staged STATIC binary and `ttl_editor.o`

The rootfs boot configuration is:

```ini
[boot]
command=/opt/404/404-init.sh

[user]
default=root

[automount]
enabled=true
mountFsTab=false
```

At boot, `404-init.sh` does the following:

1. Reads the Windows username from `/opt/404/win-user`
2. Resolves the STATIC config at `/mnt/c/Users/<WIN_USER>/AppData/Roaming/404/static/static.runtime.toml`
3. Best-effort attaches the eBPF classifier to `eth0` with `tc`
4. Starts `/opt/404/static --config <path> --mode proxy`

Boot assumptions:

- the desktop app has already written `/opt/404/win-user`
- the STATIC TOML exists at the Windows-side roaming path mounted inside WSL
- repeated boots should remain harmless because the `tc` attach path is best-effort and idempotent enough for repeated startup attempts

## Versioning

The packaging script writes `/opt/404/distro-version` into the rootfs before `docker export`, using the `--version` value passed to `build.sh`.

That file is baked into the final tarball before WSL import and is intended to stay aligned with the manifest version used by the desktop updater path.

## CI Release Flow

The release workflow is `.github/workflows/distro-release.yml`.

It runs on:

- `push` tags matching `v*`
- manual `workflow_dispatch`

High-level flow:

1. Resolve the release version from the tag or manual input
2. Install Node and Rust target tooling
3. Install Linux build dependencies including musl, clang, libbpf, and kernel libc headers
4. Build `static_proxy` for `x86_64-unknown-linux-musl`
5. Build `src/ebpf/ttl_editor.o`
6. Package `dist/404-distro.tar.gz`
7. Generate `dist/distro/manifest.json`
8. Sign the manifest with `DISTRO_MANIFEST_SIGNING_KEY`
9. Upload workflow artifacts
10. Publish stable and versioned distro assets to R2
11. Publish tarball and manifest files as GitHub Release assets

Publish layout:

Stable objects:

- `distro/manifest.json`
- `distro/manifest.json.sig`

Versioned objects:

- `distro/<tag>/404-distro.tar.gz`
- `distro/<tag>/manifest.json`
- `distro/<tag>/manifest.json.sig`

The stable manifest is intentionally `no-store` cached. The versioned tarball is immutable.

Public-origin expectation:

- the same worker-backed origin used for desktop updater delivery should also expose `/distro/manifest.json`, `/distro/manifest.json.sig`, and the versioned `/distro/<tag>/...` objects from the shared R2 bucket

## Local Verification CLI

After a tagged release publishes to the public origin, verify the stable manifest and versioned tarball with:

```sh
./scripts/verify-distro-publication.sh \
  --base-url https://updates.404privacy.com \
  --version v1.2.3
```

That script checks:

- `${BASE_URL}/distro/manifest.json` is reachable
- `${BASE_URL}/distro/manifest.json.sig` is reachable
- the stable manifest `version` matches the expected tag
- the stable manifest `artifact_path` points at `/distro/<tag>/404-distro.tar.gz`
- the versioned tarball responds publicly

Dependencies for the verification script:

- `curl`
- `node`

## Desktop Integration Assumptions

The Linux-side init script assumes Tauri writes the Windows username into:

```text
/opt/404/win-user
```

and the STATIC TOML into:

```text
/mnt/c/Users/<WIN_USER>/AppData/Roaming/404/static/static.runtime.toml
```