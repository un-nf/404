import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'

export function installNetwork() {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection
  if (!connection) { markModule('network', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  const proto = Object.getPrototypeOf(connection)
  let requested = 0, changed = 0
  for (const [key, value] of Object.entries({ downlink: fp.downlink ?? 10, effectiveType: fp.effective_type || '4g', rtt: fp.rtt ?? 50, type: fp.connection_type })) {
    if (value !== undefined) { requested++; changed += Number(replaceGetter(proto, key, () => value)) }
  }
  // saveData is an operational user preference, not persona metadata.
  markModule('network', { status: changed === requested ? 'installed' : changed ? 'partial' : 'native',
    detail: 'native event target and aliases; saveData preserved' })
}
