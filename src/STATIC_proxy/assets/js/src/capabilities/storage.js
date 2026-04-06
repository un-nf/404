import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

export function installStorage() {
  const fingerprint = getFingerprint()
  const estimateValue = Object.freeze({
    quota: fingerprint.storage_quota ?? 107374182400,
    usage: fingerprint.storage_usage ?? 1048576,
  })
  const storageObject = Object.freeze({
    estimate: markNativeCode(async function estimate() {
      return estimateValue
    }, 'estimate'),
    persisted: markNativeCode(async function persisted() {
      return true
    }, 'persisted'),
    persist: markNativeCode(async function persist() {
      return true
    }, 'persist'),
  })

  Object.defineProperty(Navigator.prototype, 'storage', {
    get: markNativeCode(function storageGetter() {
      return storageObject
    }, 'storage'),
    configurable: true,
    enumerable: true,
  })

  markModule('storage')
}