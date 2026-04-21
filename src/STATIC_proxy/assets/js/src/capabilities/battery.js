import { getFingerprint } from '../core/config.js'
import { isFirefoxLike } from '../core/browser.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function createBatteryManager() {
  return Object.freeze({
    charging: true,
    chargingTime: 0,
    dischargingTime: Infinity,
    level: 1,
    onchargingchange: null,
    onchargingtimechange: null,
    ondischargingtimechange: null,
    onlevelchange: null,
    addEventListener: markNativeCode(function addEventListener() {}, 'addEventListener'),
    removeEventListener: markNativeCode(function removeEventListener() {}, 'removeEventListener'),
    dispatchEvent: markNativeCode(function dispatchEvent() { return true }, 'dispatchEvent'),
  })
}

export function installBattery() {
  const fingerprint = getFingerprint()
  if (isFirefoxLike(fingerprint)) {
    markModule('battery')
    return
  }

  const manager = createBatteryManager()

  Object.defineProperty(Navigator.prototype, 'getBattery', {
    value: markNativeCode(async function getBattery() {
      return manager
    }, 'getBattery'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  markModule('battery')
}