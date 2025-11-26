# 404 v1.0 - The First Stable Release

This is it. The big 1.0.

This release marks the point where 404 transitions from an experimental prototype into a stable, usable platform. The core STATIC proxy, built from the ground up in Rust, is no longer just a proof-of-concept—it's a reliable engine for full-stack fingerprint control.

---

## What "1.0" Means Here

**The architecture is stable.** The `STATIC` proxy, certificate management, profile system, and stage pipeline are now considered a solid foundation to build on.

## Highlights

### 1. The STATIC Proxy is Production-Shaped

The heart of 404 is now a robust, async-native TLS-terminating proxy.
- **Login Functionality** You can now login to your Google and Microsoft services. Continue to exercise caution when handling STATIC Proxy logs.
- **Battle-Tested:** Built to handle real-world traffic and defeat commercial fingerprinting services (Fingerprint.com, DataDome, etc.).
- **Full Protocol Control:** Native HTTP/1.1 and HTTP/2 engines give us granular control over pseudo-headers, window updates, and stream management.
- **Deterministic Pipeline:** The same profile delivers the same fingerprint, every time. The request/response stages (`HeaderProfile`, `Csp`, `JsInjection`, etc.) run in a strict, predictable order.

### 2. Certificate Management You Can Trust

mitmproxy dependency from early versions is gone.
- **Automatic CA & Leaf Generation:** On first run, the proxy creates a durable root CA. It then generates and signs leaf certificates on the fly for each host you visit.
- **In-Memory Cache:** Leaf certificates are cached (24h TTL) in a lock-free `DashMap` for high-concurrency performance. No more constant disk I/O or `rcgen` calls for every single connection.
- **Clean Separation:** The CA key is loaded once and kept isolated. Leaf keys are generated and held in memory, reducing the attack surface.

### 3. Profile-Driven Everything

Magic strings and hardcoded logic are out. Behavior is now explicitly defined in JSON profiles.
- **Unified Profiles:** A single profile dictates TLS ciphers (for JA3/JA4), HTTP header order/values, and JavaScript spoofing parameters.
- **Explicit Control:** You can see exactly *why* a fingerprint is being generated. It's all in the profile.

### 4. eBPF Groundwork is Solid

The Linux eBPF module for TCP/IP-level fingerprinting is no longer just a sketch. The build system (`Makefile`) and core `ttl_editor.c` program are stable and ready for expansion.

---

## Breaking Changes from Pre-1.0 Versions

If you've been using 404 before this release, you need to be aware of these changes:

- **Certificate Layout:** The old `mitmproxy` approach is deprecated. Feel free to remove `mitmproxy` keys from your trust store. You **must** re-trust the new CA generated on the first run of v1.0. The proxy will handle the new layout automatically.
- **Profile Schema:** Profiles now follow a more structured schema. If you were using custom or modified profiles, you may need to update them to match the new format.
- **Configuration File:** The proxy now looks for a `static.toml` for configuration.

## What's Next

1.0 is the baseline, not the finish line.
- **Hardening:** Now that the core is stable, the focus shifts to hardening against edge cases, improving performance, and expanding test coverage.
- **eBPF Expansion:** More TCP/IP-level mutations and platform-specific hooks.
- **Better Tooling:** More tools and documentation for creating and validating your own profiles.
- **JS Enumeration & Hardening** I'm not a JavaScript developer (I might as well be after this), so this will most likely be refactored over time. Don't get me wrong, it works!
- **VM Images:** Work will begin on distributing dedicated, lightweight VM images for users who can't run the eBPF module natively.

## License

AGPL-3.0
