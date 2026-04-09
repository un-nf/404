# STATIC Proxy Security Audit Status

This note tracks what has already been addressed in the current pass, what still requires work in the native/Tauri repo, and what additional findings should be prioritized in later audit runs.

It is based on the original threat-model framing plus the current repo state.

## Covered In This Pass

### 1. CA private key plaintext storage

Status: addressed in this repo.

What changed:

- File-backed CA key storage was removed.
- The CA private key is now secure-storage-only.
- Windows uses a DPAPI-protected blob.
- macOS/Linux use OS keyring storage.
- The public CA certificate remains on disk.
- Managed paths were moved to OS app-data resolution instead of relative working-directory paths.

Repo locations:

- [src/STATIC_proxy/src/keystore/mod.rs](/workspaces/404/src/STATIC_proxy/src/keystore/mod.rs)
- [src/STATIC_proxy/src/config/settings.rs](/workspaces/404/src/STATIC_proxy/src/config/settings.rs)
- [src/STATIC_proxy/src/tls/cert.rs](/workspaces/404/src/STATIC_proxy/src/tls/cert.rs)

Residual risk:

- The native app must stop assuming a key file exists on disk.
- The native app must not try to inspect or migrate `static-ca.key` directly.

### 2. Unbounded request/response buffering

Status: addressed in this repo.

What changed:

- Request body buffering is capped.
- Origin response buffering is capped.
- Decompressed HTML used for JS injection is capped separately.
- Default limits are now configurable through proxy config.

Current defaults:

- Request body: `16 MiB`
- Response body: `32 MiB`
- Decompressed HTML: `16 MiB`

Repo locations:

- [src/STATIC_proxy/src/proxy/connection.rs](/workspaces/404/src/STATIC_proxy/src/proxy/connection.rs)
- [src/STATIC_proxy/src/proxy/fetcher.rs](/workspaces/404/src/STATIC_proxy/src/proxy/fetcher.rs)
- [src/STATIC_proxy/src/proxy/stages/js.rs](/workspaces/404/src/STATIC_proxy/src/proxy/stages/js.rs)
- [src/STATIC_proxy/src/config/settings.rs](/workspaces/404/src/STATIC_proxy/src/config/settings.rs)

Residual risk:

- This is still a buffering architecture, not a streaming one.
- Very large but under-limit bodies still consume memory by design.

### 3. Stale or tampered embedded JS bundle fallback

Status: addressed in this repo.

What changed:

- The build now fails closed if Node is unavailable.
- The build now fails closed if npm is unavailable.
- The build now fails closed if JS dependency install fails.
- The build now fails closed if bundling fails.
- The build now fails if the bundle was not freshly produced.

Repo locations:

- [src/STATIC_proxy/build.rs](/workspaces/404/src/STATIC_proxy/build.rs)
- [src/STATIC_proxy/src/assets.rs](/workspaces/404/src/STATIC_proxy/src/assets.rs)

Residual risk:

- A malicious local builder can still modify tracked JS sources before build.
- That is a source-control and release-trust problem, not a stale-artifact fallback problem anymore.

### 4. Release verification artifacts

Status: partially addressed in this repo.

What changed:

- Release workflow now emits per-asset SHA-256 sidecars.
- Release workflow signs checksum sidecars.
- Release workflow emits a signed release manifest.
- Release workflow emits provenance/attestation artifacts.

Repo location:

- [/.github/workflows/static-release.yml](/workspaces/404/.github/workflows/static-release.yml)

Important note:

- This only improves security if the native app verifies the signed manifest and binary digest before replacement.

## Not Covered Yet In This Repo

These are still open and should be tracked as active future work.

### 1. Unauthenticated localhost control plane

Severity: high

Why it matters:

- The control plane exposes state-changing localhost endpoints with no authentication.
- A local process can stop the proxy or initialize the CA.
- A malicious webpage may be able to trigger localhost POSTs via browser form submission or similar CSRF-style behavior, even if it cannot read the response.

Repo location:

- [src/STATIC_proxy/src/control.rs](/workspaces/404/src/STATIC_proxy/src/control.rs)

Observed endpoints:

- `/ca/init`
- `/stop`
- `/telemetry/snapshot`
- `/profiles/validate`

Recommended future fix:

1. Require an auth token or local secret.
2. Consider moving to a more restricted local transport.
3. Remove or gate dangerous debug/control endpoints in production mode.

### 2. Telemetry may expose sensitive browsing metadata

Severity: medium

Why it matters:

- Telemetry buffers recent events in memory.
- Structured events include peer and SNI metadata.
- Local control-plane telemetry reads can expose recent browsing context.
- Info-level logging can persist flow details into terminal logs or external log collectors.

Repo locations:

- [src/STATIC_proxy/src/telemetry.rs](/workspaces/404/src/STATIC_proxy/src/telemetry.rs)
- [src/STATIC_proxy/src/proxy/connection.rs](/workspaces/404/src/STATIC_proxy/src/proxy/connection.rs)

Recommended future fix:

1. Redact or minimize telemetry fields by default.
2. Make telemetry snapshot debug-only.
3. Add explicit privacy modes for production deployments.

### 3. Supply-chain hygiene in Cargo dependencies and CI

Severity: medium

Why it matters:

- There are still permissive dependency specifiers in Cargo.toml.
- CI does not yet appear to run `cargo audit`.
- The current container could not run Rust validation, so repo-side verification is still incomplete until a real Rust build happens.

Examples previously identified:

- `anyhow = "*"`
- `http = "*"`

Relevant location:

- [src/STATIC_proxy/Cargo.toml](/workspaces/404/src/STATIC_proxy/Cargo.toml)

Recommended future fix:

1. Replace wildcard versions with explicit semver ranges.
2. Add `cargo audit` to CI.
3. Run builds/tests in CI for all release-relevant changes.

### 4. Workflow trust is improved but still not sufficient on its own

Severity: medium

Why it matters:

- The workflow now emits signed metadata.
- But the workflow still has release publication authority.
- If the native app does not verify the signed manifest identity and digest, compromise of repo/release automation still means compromise of updates.

Relevant location:

- [/.github/workflows/static-release.yml](/workspaces/404/.github/workflows/static-release.yml)

Recommended future fix:

1. Enforce verification in the native app before install.
2. Consider stronger release approval controls and environment protections.
3. Consider whether `workflow_dispatch` and broad release permissions should be narrowed.

## Native/Tauri Repo Work Required

These are external to this repo, but they are required for the end-to-end threat model to improve.

### 1. Verify signed release manifest before updating STATIC

Status: not yet implemented in the native app, based on current discussion.

Required behavior:

1. Download `static_proxy-release-manifest.json`.
2. Verify its signature and signer identity.
3. Resolve the platform asset from the verified manifest.
4. Download the binary.
5. Hash the binary.
6. Compare the digest with the verified manifest.
7. Reject the update on mismatch.
8. Replace the installed binary only after all verification passes.

### 2. Enforce anti-downgrade logic

Status: not yet implemented.

Required behavior:

1. Track installed proxy version.
2. Reject lower-version updates unless rollback is explicitly enabled.

### 3. Remove old CA file-path assumptions

Status: not yet implemented in the native app.

Required behavior:

- Stop checking for a disk private-key file.
- Use only the public cert path.
- Expect startup failures when secure storage is unavailable.

Reference handoff note:

- [.REL_notes/nativeRepoHandoff.md](/workspaces/404/.REL_notes/nativeRepoHandoff.md)

## Additional Findings For Future Audit Runs

These are not yet fixed in the repo and should be revisited in later passes.

### Finding A: Production `expect`/`panic` paths still exist in runtime code

Severity: low to medium

Examples:

- app-data path resolution uses `expect(...)`
- CA generation uses `expect(...)`

Repo locations:

- [src/STATIC_proxy/src/config/settings.rs](/workspaces/404/src/STATIC_proxy/src/config/settings.rs)
- [src/STATIC_proxy/src/tls/cert.rs](/workspaces/404/src/STATIC_proxy/src/tls/cert.rs)

Why it matters:

- Panics in initialization code can become hard crashes instead of actionable operator errors.

Future fix:

- Convert runtime `expect`/`panic` paths to structured errors where practical.

### Finding B: Plain proxy mode still exists

Severity: low

Why it matters:

- A plaintext proxy mode can be useful for debugging.
- It can also become a misconfiguration footgun if used outside controlled cases.

Future fix:

- Keep it debug-only, feature-gated, or more clearly marked as non-production.

### Finding C: Certificate lifecycle still lacks rotation/expiry planning

Severity: low

Why it matters:

- The current work focused on secure storage, not certificate rotation policy.
- Future runs should evaluate CA lifetime, rotation UX, and cleanup/uninstall behavior.

Future fix:

1. Define CA validity policy.
2. Define re-init and uninstall behavior.
3. Ensure trust-store cleanup is explicit and auditable.

## Verification Gaps Right Now

These items are not design findings, but they are current audit limitations.

1. This container does not have `cargo`, so a full local Rust build/test pass could not be run here.
2. `Cargo.lock` refresh and dependency resolution still need to be validated in a Rust-enabled environment.
3. Release workflow behavior still needs to be exercised on a real tag to confirm emitted assets and signatures match the documented contract.

## Next Suggested Audit Passes

### Pass 2

Focus:

1. Authenticate or constrain the control plane.
2. Reduce telemetry sensitivity.
3. Add dependency-audit CI.

### Pass 3

Focus:

1. Native/Tauri updater verification review.
2. Trust-store installation and cleanup review.
3. Release approval and environment protection review.

### Pass 4

Focus:

1. Panic/expect cleanup in runtime code.
2. Certificate rotation and uninstall lifecycle.
3. Streaming architecture review for large bodies.
Good framing. Trail of Bits approaches this kind of engagement systematically — they’re not just looking for bugs, they’re modeling the entire trust chain. Here’s how they’d think about your system:

1. Threat Modeling First
   Before touching code they’d ask:
   ∙	Who is the adversary? Nation state? Opportunistic attacker? Malicious insider (you)?
   ∙	What’s the crown jewel? The cert? The proxy binary? The session profiles?
   ∙	What does a successful attack look like? Silent traffic interception? Persistent backdoor? Data exfiltration?
   ∙	What’s the blast radius if the update mechanism is compromised?
   The answers shape everything that follows.
2. The Update Mechanism — This Is Your Biggest Surface
   This is where they’d spend the most time given what you described.
   Questions they’d ask:
   ∙	Where does the updater fetch from? HTTPS only? Is the TLS cert pinned?
   ∙	Is the binary signed? With what — GPG, sigstore, a custom scheme?
   ∙	Where does the signing key live? On your laptop? A hardware key? A CI secret?
   ∙	Is the signing step part of the automated pipeline or a manual human step?
   ∙	What happens if signature verification fails — hard abort or soft fallback?
   ∙	Is the version check and the binary fetch the same request or separate?
   ∙	Can an attacker serve a downgrade — force the app back to an older vulnerable version?
   ∙	Is the update channel authenticated bidirectionally or just TLS to GitHub?
   What they’d look for in code:
   ∙	Is verification happening before or after the binary is written to disk?
   ∙	Is there a TOCTOU (time-of-check time-of-use) race between verification and execution?
   ∙	What’s the update process running as — user space or elevated privileges?
   ∙	If elevated, how does privilege escalation happen and is it auditable?
3. The Root Certificate
   Questions:
   ∙	How is the cert generated — on first run, at install time, shipped with the binary?
   ∙	Where is the private key stored? Plaintext on disk? Keychain/OS secret store?
   ∙	What permissions does the key file have?
   ∙	Is the cert ever transmitted anywhere or is it purely local?
   ∙	What’s the cert lifetime? Does it rotate?
   ∙	If someone extracts the private key, what’s the worst case?
   What they’d look for:
   ∙	Is key generation using a cryptographically secure RNG?
   ∙	Is the key stored in the OS keychain (good) or a file in the app directory (bad)?
   ∙	Are cert operations happening in the same process as the proxy or isolated?
4. The Proxy Architecture Itself
   Questions:
   ∙	What process model is it — single process, supervisor + worker?
   ∙	What does the proxy do with traffic it intercepts? Logged anywhere, even temporarily?
   ∙	Are session profiles written to disk? Where, what permissions, encrypted?
   ∙	Does the proxy ever phone home for anything beyond update checks?
   ∙	What happens to intercepted data on crash?
   What they’d look for:
   ∙	Memory handling around intercepted request/response data — are buffers zeroed after use?
   ∙	Is there any logging that could capture sensitive content inadvertently?
   ∙	What’s the error handling story — do panics/crashes leave artifacts?
5. The Build and Release Pipeline
   This is the supply chain question.
   Questions:
   ∙	Where does compilation happen — your machine, GitHub Actions, something else?
   ∙	Who has write access to the repo and the release pipeline?
   ∙	Are dependencies pinned to exact versions and hashes in Cargo.lock?
   ∙	Are you verifying the integrity of your own dependencies — cargo audit?
   ∙	Is the signing key accessible to CI or only to a human?
   ∙	Are releases tagged and is the tag signed with a GPG key?
   What they’d look for:
   ∙	Unpinned dependencies that could be silently updated upstream
   ∙	CI secrets that if leaked give an attacker release signing capability
   ∙	Whether a compromised GitHub account alone is sufficient to push a malicious release
6. The Rust-Specific Questions
   Trail of Bits has deep Rust expertise. They’d look at:
   ∙	Use of unsafe blocks — where, why, are they actually necessary?
   ∙	Any FFI boundaries — what’s on the other side?
   ∙	Are you using unwrap() or expect() in places that could panic in production on malformed input?
   ∙	Dependency tree — how many transitive dependencies, any with known advisories?
   ∙	Are you running cargo audit in CI?
7. The Certificate Trust Installation
   Questions:
   ∙	How does the cert get installed into the system trust store?
   ∙	Does that step require elevated privileges? How is that handled?
   ∙	Is the user clearly informed what they’re consenting to at that moment?
   ∙	Can the cert be cleanly uninstalled — does uninstalling 404 remove it?
   ∙	On macOS specifically — are you using the keychain API or dropping files into a trust store directory?

The Meta-Question They’d End With
After all of that, Trail of Bits would ask: given everything we found, what’s the minimum foothold an attacker needs to intercept a user’s HTTPS traffic silently?
If the answer is “compromise your GitHub account and push a release” — that’s a real and specific risk worth addressing before you have the kind of adoption where someone would bother trying.
The most immediate thing I’d look at tomorrow: is the signing key air-gapped from CI? That single question probably tells you the most about where you actually stand.​​​​​​​​​​​​​​​​