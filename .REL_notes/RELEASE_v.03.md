# 404 v.03 Release Notes

## What Changed

v.03 rewrites the JavaScript injection architecture.

## New: Modular 4-Layer Injection Architecture

**What it does:**
- Intercepts eval() and Function() constructor before page scripts execute
- Validates execution order and dependency chains at runtime
- Separates configuration, API replacement, and advanced protections
- Reduces detection surface via stack trace sanitization and Symbol obfuscation

## Architecture: The 4 Layers

**Layer 0: Bootstrap (0bootstrap.js)**
Runs first. Establishes execution environment control.

- **eval() wrapper** - Injects spoofed bindings into evaluated code
- **Function() wrapper** - Same for new Function() constructor
- **Script interception** - Monitors createElement('script') and appendChild() for dynamic scripts
- **Iframe propagation** - MutationObserver detects new iframes and reinjects all 4 layers
- **Stack trace sanitization** - Overrides Error.prototype.stack getter to remove detection markers ('404', 'wrapper', '__fp')
- **CSP nonce detection** - Extracts nonce from document.currentScript for dynamic script injection

Sets `window.__404_bootstrap_active` flag. All subsequent layers validate this exists.

**Layer 1: Globals Shim (1globals_shim.js)**
Runs second. Replaces browser APIs with Proxy objects.

- **navigator Proxy** - Intercepts userAgent, platform, vendor, hardwareConcurrency, languages, etc.
- **screen Proxy** - Spoofs resolution, availWidth/Height, colorDepth
- **performance Proxy** - Adds timing jitter to performance.now()
- **PRNG** - Seeded by profile name + session ID for consistent randomization
- **Fallback chains** - Returns original values if config missing

Creates `window.__404_spoofed_globals` object containing Proxy wrappers. Bootstrap layer injects this into eval() contexts so dynamically executed code sees spoofed values.

Sets `window.__404_shim_active` flag.

**Layer 2: Config Layer (config_layer.js)**
Runs third. Loads and validates fingerprint profile.

- **Profile loading** - Parses `{{config_json}}` placeholder injected by js_injector.py
- **Required field validation** - Ensures user_agent, platform, canvas_hash, webgl_vendor/renderer exist
- **Coherence checking** - Validates UA ↔ platform ↔ vendor consistency (e.g., Windows UA must have Win32/Win64 platform)
- **Format validation** - Checks screen_resolution matches /^\d+x\d+$/ regex
- **Browser-specific validation** - Warns if Firefox profile contains Client Hints

Sets `window.__404_config_ready` flag. Layer 3 aborts if this is missing.

**Layer 3: Advanced Protections (2fingerprint_spoof_v2.js)**
Runs last. Applies canvas noise, WebGL spoofing, and obfuscation.

- **Canvas noise** - Modifies getImageData() with per-pixel PRNG seeding (interval=10 for normal images, interval=20 for favicons)
- **WebGL spoofing** - Overrides getParameter() to return spoofed vendor/renderer strings
- **Audio context protection** - Adds noise to AudioBuffer.getChannelData()
- **Fingerprint drift** - Generates per-session ID mixed into canvas/audio hashes to prevent cross-session correlation
- **Session ID generation** - Combines Date.now() + Math.random() + performance.now() for entropy
- **Symbol obfuscation** - Creates Symbol.for() aliases for __404_* globals (non-enumerable, hidden from Object.keys())
- **Version string cleanup** - Deletes version properties after initialization (reduces detection surface by 4 properties)

Sets `window.__404_advanced_protections_active` flag.

## Limitations

**Known issues NOT fixed:**
- eval() template literal vulnerability (${} evaluation in injected code)
- PRNG predictability (profile name in seed without true randomness)

**Breakage:**
- Chrome login flows fragile (Google: no-go, Microsoft: intermittent)
- Firefox more stable but still breaks occasionally - **Can login to Google services with Firefox!**
- Canvas noise may trigger anti-bot systems on strict sites - *should* be consistent per visit.

## Detection Surface Analysis

**What remains visible:**
- 8 core globals required for runtime functionality (__404_bootstrap_active, __404_shim_active, __404_config_ready, __404_advanced_protections_active, __404_spoofed_globals, __404_session_id, __404_canvas_fingerprint, __fpConfig)
- Proxy wrappers detectable via Proxy.revocable() or performance tests
- WebGL parameter mismatches (e.g., Chrome UA with Firefox-style WebGL renderer)

**What's now hidden:**
- Version strings (__404_bootstrap_version, __404_shim_version, etc.) - deleted after init
- Stack trace artifacts - sanitized to remove '404'/'wrapper'/'__fp' patterns
- Symbol aliases - non-enumerable, won't appear in Object.keys() or for...in loops
- eval() wrapper internals - function names scrubbed from Error.stack

## License

AGPL-3.0
