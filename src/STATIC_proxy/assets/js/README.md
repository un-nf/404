# STATIC JavaScript runtime

This directory contains the browser-side runtime injected by STATIC. It adjusts selected browser observations to match the active profile; it does not provide a second browser engine or replace physical devices, codecs, fonts, graphics drivers, or audio hardware.

## Source layout

- [`src/runtime.js`](src/runtime.js) starts the runtime in a page.
- [`src/core/`](src/core/) contains configuration handling, captured built-ins, private state, patch installation and rollback, policy, and shared runtime helpers.
- [`src/identity/`](src/identity/) covers browser and device identity observations such as navigator, screen, date/time, fonts, and performance.
- [`src/capabilities/`](src/capabilities/) handles capability and permission observations, including storage and media capabilities.
- [`src/spoofing/`](src/spoofing/) contains canvas, audio, WebGL, media-device, speech, gamepad, event-timing, and WebRTC interventions.
- [`src/contexts/`](src/contexts/) contains the worker entry points. The build produces separate classic-worker and module-worker bundles.
- [`src/privacy/`](src/privacy/) contains privacy-related request and beacon handling.
- [`../../schema/`](../../schema/) defines the shared runtime profile and WebGL parameter data.

The Rust proxy selects and validates profiles, applies configured overrides, and supplies the runtime configuration. The JavaScript runtime consumes that profile; it does not select a persona based on the host machine or query physical storage capacity to construct one.

## Runtime invariants

- Keep runtime state, configuration, and captured native references private to the runtime closure. Do not expose them on `window`, worker globals, or public prototypes.
- Capture built-ins and native references before installing patches. Runtime bookkeeping should use those captured operations rather than page-mutable methods.
- Validate and copy profile data before use. Treat profile input as data, not executable code.
- Preserve native receiver checks, descriptors, and public result shapes where an API is wrapped. Reject invalid or unsupported inputs explicitly rather than manufacturing plausible native results.
- Install patches through the existing lifecycle and rollback helpers. A failed installation must not leave a partially patched realm; resources and wrappers must be released with their owning realm.
- Keep interventions scoped to the observations selected by policy. Do not broaden changes to unrelated host behavior.

These constraints do not guarantee protection against code that runs before the runtime, browser-engine internals, or independently delivered bundles. A completed runtime entry point is not proof that every browser surface or child realm is covered.

## Profile and API behavior

- Rust and JavaScript share [`../../schema/runtime-profile.schema.json`](../../schema/runtime-profile.schema.json), [`../../schema/webgl-parameters.json`](../../schema/webgl-parameters.json), and validation fixtures. Update the schema, profile data, and relevant tests together when changing the profile contract.
- Storage quota and usage are fixed advertised values supplied by the proxy. Actual allocation, persistence, and physical capacity remain browser/host behavior.
- User-Agent Client Hints are constructed from requested profile fields after validating the receiver; the runtime does not fetch a native high-entropy result and then edit it. Browser promise resolution and argument-conversion behavior still need to match the native API.
- Date and `Intl` observations use the profile timezone for covered operations. Legacy local date-string handling is controlled by the profile policy.
- Canvas readback operates on copies. The default noise mode remains approximately recoverable; redacted readback is a restriction, not a rendering substitute.
- Audio, WebGL, media, font, and WebRTC changes affect observations, not the underlying implementation. Missing codecs, devices, fonts, extensions, or hardware are not created by the runtime.
- Worker rewriting has limits: cached, blob, data, and pre-existing workers, early child code, CSP/Trusted Types restrictions, and worklet processors are not universally covered.
- WebRTC address rewriting can affect connectivity. Relay preservation and address masking are separate policies; real peer/TURN behavior must be tested for the intended deployment.

Do not describe the runtime as providing complete browser parity or unlinkability. Record known limits alongside any new intervention, especially where behavior can change audio output, rendering, or connectivity.

## Build and test

Run JavaScript commands from `src/STATIC_proxy/build`:

```text
npm ci
npm test
npm run build
node build.js --verify
```

The build creates three outputs under `assets/js/dist`: `runtime.bundle.js`, `worker-classic.bundle.js`, and `worker-module.bundle.js`. It writes `bundle-set.json` last; verification checks the outputs against their source, schemas, builder, and locked dependencies. Use the matched set—do not copy or publish an individual bundle from a different build.

Run the Rust tests and build from `src/STATIC_proxy`:

```text
cargo test --locked
cargo build --locked
```

Node tests exercise source-level behavior. Browser fixtures under [`../../tests/`](../../tests/) require their documented browser and environment setup; passing source tests alone does not establish browser behavior. Check the relevant test and workflow before changing a runtime surface, and report which browser or integration checks were actually run.