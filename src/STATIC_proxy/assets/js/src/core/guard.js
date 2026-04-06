const RUNTIME_VERSION = '5.0.0'
const REGISTRY_KEY = '__STATIC_RUNTIME__'

export function initRuntime() {
  const existing = window[REGISTRY_KEY]
  if (existing && existing.version === RUNTIME_VERSION) {
    return false
  }

  window[REGISTRY_KEY] = {
    version: RUNTIME_VERSION,
    config: null,
    policy: null,
    entropy: null,
    modules: {},
    nativeRefs: {},
    nonce: null,
  }

  return true
}

export function getRuntime() {
  return window[REGISTRY_KEY]
}

export function markModule(name) {
  const runtime = getRuntime()
  if (runtime) {
    runtime.modules[name] = true
  }
}