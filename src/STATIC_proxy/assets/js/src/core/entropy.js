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

export function initEntropy() {
  const runtime = getRuntime()
  const fingerprint = runtime.config?.fingerprint || {}
  const driftEnabled = fingerprint.enable_fingerprint_drift !== false
  const sessionId = driftEnabled
    ? (Date.now() ^ ((Math.random() * 0xFFFFFFFF) >>> 0)).toString(36)
    : 'static'
  const sessionSeed = hashString(`${sessionId}:${fingerprint.canvas_hash || ''}`)
  const origin = (() => {
    try {
      return location.origin
    } catch {
      return 'opaque'
    }
  })()
  const originSeed = hashString(`${sessionId}:${origin}`)

  runtime.entropy = {
    sessionId,
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