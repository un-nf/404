import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

export function installEventTimingSpoof() {
  const runtime = getRuntime()
  const descriptor = runtime.nativeRefs.eventTimeStampDescriptor
  if (!descriptor?.get || runtime.modules.eventTiming) {
    return
  }

  const offsets = new WeakMap()

  Object.defineProperty(runtime.nativeRefs.eventPrototype, 'timeStamp', {
    configurable: true,
    enumerable: descriptor.enumerable,
    get: markNativeCode(function timeStamp() {
      const base = descriptor.get.call(this)
      let offset = offsets.get(this)
      if (offset === undefined) {
        const seed = runtime.entropy.hash(`${this?.type || 'event'}:${base}:${runtime.entropy.sessionId}`)
        const rng = runtime.entropy.rng(seed)
        offset = (rng() - 0.5) * 0.75
        offsets.set(this, offset)
      }
      return base + offset
    }, 'timeStamp'),
  })

  markModule('eventTiming')
}