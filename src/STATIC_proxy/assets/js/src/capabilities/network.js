import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'
import { suppressNativeTransitions } from '../core/events.js'

export function installNetwork() {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection
  if (!connection) { markModule('network', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  for(const target of new Set([navigator.connection,navigator.mozConnection,navigator.webkitConnection].filter(Boolean))) {
    suppressNativeTransitions(target,['change','typechange'])
  }
  const prototypes = new Set([navigator.connection,navigator.mozConnection,navigator.webkitConnection].filter(Boolean).map(value=>Object.getPrototypeOf(value)))
  let requested = 0, changed = 0
  for (const proto of prototypes) for (const [key, value] of Object.entries({ downlink: fp.downlink, effectiveType: fp.effective_type, rtt: fp.rtt, type: fp.connection_type, saveData: fp.save_data ?? false })) {
    if (value !== undefined) { requested++; changed += Number(replaceGetter(proto, key, () => value)) }
  }
  markModule('network', { status: changed === requested ? 'installed' : changed ? 'partial' : 'native',
    detail: 'profile observations across present native aliases; trusted backend transitions suppressed; throughput/transport remain native' })
}
