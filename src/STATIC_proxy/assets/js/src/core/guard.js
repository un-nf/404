const RUNTIME_VERSION = '5.0.0'
let runtime = null

export function initRuntime() {
  if (runtime) {
    if (runtime.state === 'failed' && runtime.retryable !== false) {
      runtime.state = 'initializing'
      runtime.attempts += 1
      return true
    }
    return false
  }

  runtime = {
    version: RUNTIME_VERSION,
    state: 'initializing',
    config: null,
    policy: null,
    entropy: null,
    modules: Object.create(null),
    outcomes: Object.create(null),
    coverage: Object.create(null),
    nativeRefs: Object.create(null),
    nonce: null,
    attempts: 1,
  }

  return true
}

export function getRuntime() {
  return runtime
}

export function finishRuntime(error = null) {
  const failures = Object.values(runtime.outcomes).filter((outcome) => outcome.status === 'failed')
  runtime.state = error || failures.length ? 'failed' : 'ready'
  runtime.retryable = failures.every((outcome) => outcome.rolledBack)
  runtime.failure = error ? String(error.message || error) : null
}

export function markModule(name, outcome = { status: 'installed' }) {
  const runtime = getRuntime()
  if (runtime) {
    runtime.modules[name] = true
    runtime.outcomes[name] = Object.freeze({ ...outcome })
  }
}
