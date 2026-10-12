import { markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'

export function installBattery() {
  const proto = globalThis.BatteryManager?.prototype
  if (!proto || typeof navigator.getBattery !== 'function') {
    markModule('battery', { status: 'unavailable' }); return
  }
  // Keep native promise/manager identity, permissions and EventTarget behavior.
  let changed = 0
  for (const [key, value] of Object.entries({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 })) {
    changed += Number(replaceGetter(proto, key, () => value))
  }
  markModule('battery', { status: changed === 4 ? 'installed' : changed ? 'partial' : 'native',
    detail: 'native manager; constant observations on patchable getters' })
}
