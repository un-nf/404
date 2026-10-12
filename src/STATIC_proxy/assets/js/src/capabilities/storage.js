import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { mapMethod } from '../core/descriptors.js'

export function normalizeStorageEstimate(result, fp) {
  const quantum = fp.storage_usage_quantum ?? 1048576
  const floor = fp.storage_usage ?? quantum
  const usage = Math.max(floor, Math.ceil((result.usage || 0) / quantum) * quantum)
  const quota = Math.max(fp.storage_quota ?? 107374182400, usage)
  const normalized = { ...result, quota, usage }
  // Per-backend sizes bypass aggregate bucketing and expose browsing history.
  if ('usageDetails' in normalized) normalized.usageDetails = {}
  return normalized
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
    detail: 'profile quota and bucketed usage; native persistence/allocation/OPFS' })
}
