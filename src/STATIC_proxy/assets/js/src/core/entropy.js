import { getRuntime } from './guard.js'

function xorshift32(seed) {
  let state = (seed >>> 0) || 1
  return function next() {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return (state >>> 0) / 0x100000000
  }
}

function hashString(input) {
  let hash = 0x811c9dc5
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash
}

function secureRandomUint32() {
  if (globalThis.crypto?.getRandomValues) {
    return globalThis.crypto.getRandomValues(new Uint32Array(1))[0]
  }
  return (Date.now() >>> 0)
}

export function initEntropy() {
  const runtime = getRuntime()
  const fingerprint = runtime.config?.fingerprint || {}
  const startupSalt = String(runtime.config?.raw?.startup_salt || '')
  const driftEnabled = fingerprint.enable_fingerprint_drift !== false
  const sessionId = driftEnabled
    // Public bootstrap salts are correlation tokens, not private noise keys.
    ? (globalThis.crypto?.getRandomValues ? Array.from(crypto.getRandomValues(new Uint32Array(4)), (value) => value.toString(16).padStart(8, '0')).join('') :
      `${Date.now().toString(36)}:${secureRandomUint32().toString(36)}`)
    : 'static'
  const origin = (() => {
    try {
      return typeof globalThis.origin === 'string' ? globalThis.origin : location.origin
    } catch {
      return 'opaque'
    }
  })()
  const realm = typeof WorkerGlobalScope === 'function' && globalThis instanceof WorkerGlobalScope ? 'worker' : 'window'
  const sessionSeed = hashString(`${sessionId}:${origin}:${realm}:${fingerprint.canvas_hash || ''}`)
  const originSeed = hashString(`${sessionId}:${origin}`)

  runtime.entropy = Object.freeze({
    sessionId,
    origin,
    realm,
    startupSalt,
    sessionSeed,
    originSeed,
    sessionRng: xorshift32(sessionSeed),
    originRng: xorshift32(originSeed),
    hash: hashString,
    rng: xorshift32,
  })

}
