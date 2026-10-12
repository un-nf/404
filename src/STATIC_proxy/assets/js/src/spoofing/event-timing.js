import { markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'
import { coarsenTime } from '../core/clock.js'

export function installEventTimingSpoof() {
  const installed = replaceGetter(globalThis.Event?.prototype, 'timeStamp', coarsenTime)
  markModule('eventTiming', { status: installed ? 'installed' : 'unavailable',
    detail: 'same coarsening as performance.now; native timestamp domain preserved' })
}
