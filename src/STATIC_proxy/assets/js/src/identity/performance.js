import { iterate } from '../core/primordials.js';
import { WeakMapIntrinsic as WeakMap, SetIntrinsic as Set } from '../core/primordials.js';
import { markModule } from '../core/guard.js';
import { findDescriptor, replaceGetter, mapMethod } from '../core/descriptors.js';
import { coarsenTime } from '../core/clock.js';
export function installPerformance() {
    const proto = globalThis.Performance?.prototype;
    if (!proto) {
        markModule('performance', { status: 'unavailable' });
        return;
    }
    mapMethod(proto, 'now', coarsenTime);
    const patched = new WeakMap();
    const times = ['startTime', 'duration', 'workerStart', 'redirectStart', 'redirectEnd', 'fetchStart',
        'domainLookupStart', 'domainLookupEnd', 'connectStart', 'connectEnd', 'secureConnectionStart',
        'requestStart', 'responseStart', 'responseEnd', 'firstInterimResponseStart', 'finalResponseHeadersStart',
        'unloadEventStart', 'unloadEventEnd', 'domInteractive', 'domContentLoadedEventStart', 'domContentLoadedEventEnd',
        'domComplete', 'loadEventStart', 'loadEventEnd', 'activationStart', 'criticalCHRestart',
        'processingStart', 'processingEnd', 'renderStart', 'styleAndLayoutStart', 'firstUIEventTimestamp',
        'blockingDuration', 'executionStart', 'forcedStyleAndLayoutDuration', 'pauseDuration'];
    function once(target, key, patch) {
        const owner = findDescriptor(target, key)?.owner;
        if (!owner)
            return;
        const keys = patched.get(owner) || new Set();
        if (keys.has(key))
            return;
        keys.add(key);
        patched.set(owner, keys);
        patch();
    }
    for (const constructor of iterate([globalThis.PerformanceEntry, globalThis.PerformanceResourceTiming,
        globalThis.PerformanceNavigationTiming, globalThis.PerformanceEventTiming, globalThis.PerformancePaintTiming,
        globalThis.PerformanceLongAnimationFrameTiming, globalThis.PerformanceScriptTiming])) {
        const entryProto = constructor?.prototype;
        if (!entryProto)
            continue;
        // Only timing observations, not transfer sizes, counters or other numbers.
        for (const key of iterate(times))
            once(entryProto, key, () => replaceGetter(entryProto, key, coarsenTime));
        once(entryProto, 'toJSON', () => mapMethod(entryProto, 'toJSON', (result, entry) => {
            for (const key of iterate(times))
                if (key in result && typeof result[key] === 'number')
                    result[key] = entry[key];
            return result;
        }));
    }
    markModule('performance', { status: 'partial', detail: 'native entries/observers; timing fields coarsened; byte sizes/counters retain meaning' });
}
