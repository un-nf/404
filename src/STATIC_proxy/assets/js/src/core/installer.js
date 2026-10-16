import { ObjectIntrinsic as Object, StringIntrinsic as String } from './primordials.js';
import { getRuntime } from './guard.js';
import { transaction } from './patches.js';
export function installModule(name, enabled, installer) {
    const runtime = getRuntime();
    if (!enabled) {
        runtime.outcomes[name] = Object.freeze({ status: 'disabled', changed: 0 });
        return;
    }
    // Retry only a rolled-back failed module, using the original captured refs.
    if (runtime.modules[name])
        return;
    try {
        const result = transaction(installer);
        const reported = runtime.outcomes[name]?.status === 'failed' ? null : runtime.outcomes[name];
        const status = reported?.status === 'installed' && result.skipped.length ? 'partial' :
            reported?.status === 'installed' && !result.changed ? 'native' :
                reported?.status || (result.changed ? 'installed' : 'unavailable');
        runtime.modules[name] = true;
        runtime.outcomes[name] = Object.freeze({ ...reported, status, ...result });
    }
    catch (error) {
        runtime.modules[name] = false;
        runtime.outcomes[name] = Object.freeze({ status: 'failed', error: String(error.message || error),
            rolledBack: !error.rollbackErrors?.length, rollbackErrors: Object.freeze(error.rollbackErrors || []) });
    }
}
