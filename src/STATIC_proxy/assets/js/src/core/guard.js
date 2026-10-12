const RUNTIME_VERSION = '5.0.0'
let runtime = null

export function initRuntime() {
  if (runtime) {
    return false
  }

  runtime = {
    version: RUNTIME_VERSION,
    state: 'initializing',
    config: null,
    policy: null,
    entropy: null,
    modules: {},
    outcomes: {},
    coverage: {},
    nativeRefs: {},
    nonce: null,
  }

  return true
}

export function getRuntime() {
  return runtime
}

export function finishRuntime(error = null) {
  runtime.state = error ? 'failed' : 'ready'
  runtime.failure = error ? String(error.message || error) : null
}

export function markModule(name, outcome = { status: 'installed' }) {
  const runtime = getRuntime()
  if (runtime) {
    runtime.modules[name] = true
    runtime.outcomes[name] = Object.freeze({ ...outcome })
  }
}
