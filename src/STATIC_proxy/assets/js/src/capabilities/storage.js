import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { mapMethod } from '../core/descriptors.js'

export function normalizeStorageEstimate(result, fp) {
  // Only the declared observation contract is returned. Future native fields
  // cannot silently add a backend or disk-dependent fingerprint channel.
  return { quota: fp.storage_quota, usage: fp.storage_usage }
}

export function installStorage() {
  const storage = navigator.storage
  if (!storage) { markModule('storage', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  const installed = mapMethod(storage, 'estimate', (promise) =>
    promise.then((result) => normalizeStorageEstimate(result, fp)))
  // Persistence is a durability guarantee, not an estimate. Never fabricate a
  // successful grant. Observation masking does not allocate or constrain disk.
  markModule('storage', { status: installed ? 'partial' : 'native',
    detail: 'fixed effective-profile quota/usage; genuine persistence/allocation/OPFS; write-failure probing remains' })
}
