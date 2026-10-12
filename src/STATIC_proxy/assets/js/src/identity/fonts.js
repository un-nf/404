import { getRuntime, markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'

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

  replaceGetter(htmlElementPrototype, 'offsetWidth', (value, element) =>
    perturbMetric(value, getDelta(widthDeltaCache, element, rng)))
  replaceGetter(htmlElementPrototype, 'offsetHeight', (value, element) =>
    perturbMetric(value, getDelta(heightDeltaCache, element, rng)))

  markModule('fontMetrics')
}