import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const widthDeltaCache = new WeakMap()
const heightDeltaCache = new WeakMap()

function getDelta(cache, value, rng) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) {
    return 0
  }

  if (cache.has(value)) {
    return cache.get(value)
  }

  const delta = Math.floor(rng() * 3) - 1
  cache.set(value, delta)
  return delta
}

function perturbMetric(value, delta) {
  if (!Number.isFinite(value) || value <= 0) {
    return value
  }

  return Math.max(0, value + delta)
}

export function installFontMetrics() {
  const runtime = getRuntime()
  if (runtime.modules.fontMetrics) {
    return
  }

  const defineProperty = runtime.nativeRefs.defineProperty
  const getOwnPropertyDescriptor = runtime.nativeRefs.getOwnPropertyDescriptor
  const htmlElementPrototype = runtime.nativeRefs.HTMLElementPrototype
  if (!defineProperty || !getOwnPropertyDescriptor || !htmlElementPrototype) {
    return
  }

  const offsetWidthDescriptor = getOwnPropertyDescriptor(htmlElementPrototype, 'offsetWidth')
  const offsetHeightDescriptor = getOwnPropertyDescriptor(htmlElementPrototype, 'offsetHeight')
  if (typeof offsetWidthDescriptor?.get !== 'function' || typeof offsetHeightDescriptor?.get !== 'function') {
    return
  }

  const rng = runtime.entropy?.sessionRng ?? Math.random.bind(Math)

  defineProperty(htmlElementPrototype, 'offsetWidth', {
    get: markNativeCode(function offsetWidth() {
      const value = offsetWidthDescriptor.get.call(this)
      return perturbMetric(value, getDelta(widthDeltaCache, this, rng))
    }, 'offsetWidth'),
    configurable: true,
    enumerable: offsetWidthDescriptor.enumerable ?? false,
  })

  defineProperty(htmlElementPrototype, 'offsetHeight', {
    get: markNativeCode(function offsetHeight() {
      const value = offsetHeightDescriptor.get.call(this)
      return perturbMetric(value, getDelta(heightDeltaCache, this, rng))
    }, 'offsetHeight'),
    configurable: true,
    enumerable: offsetHeightDescriptor.enumerable ?? false,
  })

  markModule('fontMetrics')
}