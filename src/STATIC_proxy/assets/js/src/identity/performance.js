import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const entryProxyCache = new WeakMap()

function sanitizeEntry(entry) {
  if (!entry || (typeof entry !== 'object' && typeof entry !== 'function')) {
    return entry
  }

  const cached = entryProxyCache.get(entry)
  if (cached) {
    return cached
  }

  const proxy = new Proxy(entry, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target)
      if (typeof value === 'number' && prop !== 'entryType') {
        return Math.round(value * 10) / 10
      }
      if (typeof value === 'function') {
        return value.bind(target)
      }
      return value
    },
  })

  entryProxyCache.set(entry, proxy)
  return proxy
}

function sanitizeEntries(entries) {
  return entries.map((entry) => sanitizeEntry(entry))
}

export function installPerformance() {
  const runtime = getRuntime()
  const nativeNow = runtime.nativeRefs.performanceNow
  const jitter = () => (runtime.entropy?.sessionRng() ?? Math.random()) * 0.1

  Object.defineProperty(Performance.prototype, 'now', {
    value: markNativeCode(function now() {
      return nativeNow() + jitter()
    }, 'now'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  for (const name of ['getEntries', 'getEntriesByType', 'getEntriesByName']) {
    const original = Performance.prototype[name]
    if (typeof original !== 'function') {
      continue
    }
    Object.defineProperty(Performance.prototype, name, {
      value: markNativeCode(function performanceMethod(...args) {
        return sanitizeEntries(original.apply(this, args))
      }, name),
      configurable: true,
      writable: true,
      enumerable: false,
    })
  }

  markModule('performance')
}