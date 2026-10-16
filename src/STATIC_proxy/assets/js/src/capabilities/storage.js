import { promiseThen } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { replaceMethod, findDescriptor } from '../core/descriptors.js';
import { ReflectIntrinsic as Reflect } from '../core/primordials.js';
export function normalizeStorageEstimate(result, fp) {
    // Only the declared observation contract is returned. Future native fields
    // cannot silently add a backend or disk-dependent fingerprint channel.
    return { quota: fp.storage_quota, usage: fp.storage_usage };
}
export function installStorage() {
    const storage = navigator.storage;
    if (!storage) {
        markModule('storage', { status: 'unavailable' });
        return;
    }
    const fp = getFingerprint();
    const persisted=findDescriptor(storage,'persisted')?.descriptor.value;
    // Do not obtain a raw quota dictionary merely to discard it: engine-side
    // thenable resolution can consult page prototypes before JS normalization.
    // persisted() validates the genuine receiver and returns a primitive bool,
    // without requesting a grant. Actual persistence APIs remain unchanged.
    const installed = replaceMethod(storage, 'estimate', (_native,receiver) => {
        if(typeof persisted!=='function')throw new DOMException('Storage estimate masking requires native receiver validation','NotSupportedError');
        return promiseThen(Reflect.apply(persisted,receiver,[]),()=>normalizeStorageEstimate(null,fp));
    });
    // Persistence is a durability guarantee, not an estimate. Never fabricate a
    // successful grant. Observation masking does not allocate or constrain disk.
    markModule('storage', { status: installed ? 'partial' : 'native',
        detail: 'fixed effective-profile quota/usage; genuine persistence/allocation/OPFS; write-failure probing remains' });
}
