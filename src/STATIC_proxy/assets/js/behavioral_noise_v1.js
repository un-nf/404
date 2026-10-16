/* STATIC Proxy (AGPL-3.0): retired experimental behavioral envelope shim.
 * Not imported by the privacy runtime. Its historical payload/queue contract
 * was unsafe and did not demonstrate fingerprint protection. Preserved for
 * engineering review in docs/javascript-overhaul/archive/. No viewer, fake
 * analytics payload, public mutable queue or WebSocket replacement is shipped.
 */
;(function () {
  'use strict'
  if (window.__STATIC_BEHAVIOR_ENABLED === true)
    throw new Error('STATIC behavioral envelope v1 is retired; use explicit privacy request policy')
})()