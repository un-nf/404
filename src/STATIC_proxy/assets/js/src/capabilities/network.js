import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

export function installNetwork() {
  const fingerprint = getFingerprint()
  const connection = Object.freeze({
    downlink: fingerprint.downlink ?? 10,
    effectiveType: fingerprint.effective_type || '4g',
    onchange: null,
    rtt: fingerprint.rtt ?? 50,
    saveData: false,
    type: fingerprint.connection_type || 'wifi',
    addEventListener: markNativeCode(function addEventListener() {}, 'addEventListener'),
    removeEventListener: markNativeCode(function removeEventListener() {}, 'removeEventListener'),
    dispatchEvent: markNativeCode(function dispatchEvent() { return true }, 'dispatchEvent'),
  })

  Object.defineProperty(Navigator.prototype, 'connection', {
    get: markNativeCode(function connectionGetter() {
      return connection
    }, 'connection'),
    configurable: true,
    enumerable: true,
  })

  markModule('network')
}