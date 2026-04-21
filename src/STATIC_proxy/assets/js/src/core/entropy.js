import { getRuntime } from './guard.js'

function xorshift32(seed) {
  let state = (seed >>> 0) || 1
  return function next() {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return (state >>> 0) / 0xFFFFFFFF
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
    ? (startupSalt || (Date.now() ^ secureRandomUint32()).toString(36))
    : 'static'
  const origin = (() => {
    try {
      return location.origin
    } catch {
      return 'opaque'
    }
  })()
  const sessionSeed = hashString(`${sessionId}:${origin}:${fingerprint.canvas_hash || ''}`)
  const originSeed = hashString(`${sessionId}:${origin}`)

  runtime.entropy = {
    sessionId,
    origin,
    startupSalt,
    sessionSeed,
    originSeed,
    sessionRng: xorshift32(sessionSeed),
    originRng: xorshift32(originSeed),
    hash: hashString,
    rng: xorshift32,
  }

  Object.defineProperty(window, '__static_rng', {
    get: () => runtime.entropy.sessionRng,
    configurable: true,
    enumerable: false,
  })
  Object.defineProperty(window, '__static_hash', {
    get: () => runtime.entropy.hash,
    configurable: true,
    enumerable: false,
  })
}