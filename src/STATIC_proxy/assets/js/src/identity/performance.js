import { markModule } from '../core/guard.js'
import { findDescriptor, replaceGetter, mapMethod } from '../core/descriptors.js'
import { coarsenTime } from '../core/clock.js'

export function installPerformance() {
  const proto = globalThis.Performance?.prototype
  if (!proto) { markModule('performance', { status: 'unavailable' }); return }
  mapMethod(proto, 'now', coarsenTime)
  const patched = new WeakMap()
  function once(target, key, patch) {
    const owner = findDescriptor(target, key)?.owner
    if (!owner) return
    const keys = patched.get(owner) || new Set()
    if (keys.has(key)) return
    keys.add(key); patched.set(owner, keys); patch()
  }
  for (const constructor of [globalThis.PerformanceEntry, globalThis.PerformanceResourceTiming,
    globalThis.PerformanceNavigationTiming, globalThis.PerformanceEventTiming, globalThis.PerformancePaintTiming]) {
    const entryProto = constructor?.prototype
    if (!entryProto) continue
    // Only timing observations, not transfer sizes, counters or other numbers.
    for (const key of ['startTime', 'duration']) once(entryProto, key, () => replaceGetter(entryProto, key, coarsenTime))
    once(entryProto, 'toJSON', () => mapMethod(entryProto, 'toJSON', (result, entry) => ({ ...result, startTime: entry.startTime, duration: entry.duration })))
  }
  markModule('performance', { status: 'partial', detail: 'native entries/observers; now/startTime/duration coarsened; other fields native' })
}
