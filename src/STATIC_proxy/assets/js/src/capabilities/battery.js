import { iterateEntries } from '../core/primordials.js';
import { promiseThen, ObjectIntrinsic as Object, NumberIntrinsic as Number, WeakMapIntrinsic as WeakMap } from '../core/primordials.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, mapMethod } from '../core/descriptors.js';
import { getFingerprint } from '../core/config.js';
import { suppressNativeTransitions } from '../core/events.js';
export function installBattery() {
    const proto = globalThis.BatteryManager?.prototype;
    if (!proto || typeof navigator.getBattery !== 'function') {
        markModule('battery', { status: 'unavailable' });
        return;
    }
    // Keep native promise/manager identity, permissions and EventTarget behavior.
    const battery = getFingerprint().battery;
    let changed = 0;
    for (const [key, value] of iterateEntries(Object.entries({ charging: battery.charging, chargingTime: battery.charging_time ?? Infinity,
        dischargingTime: battery.discharging_time ?? Infinity, level: battery.level }))) {
        changed += Number(replaceGetter(proto, key, () => value));
    }
    const promises = new WeakMap();
    mapMethod(navigator, 'getBattery', promise => {
        if (!promises.has(promise))
            promises.set(promise, promiseThen(promise, manager => {
                suppressNativeTransitions(manager, ['chargingchange', 'chargingtimechange', 'dischargingtimechange', 'levelchange']);
                return manager;
            }));
        return promises.get(promise);
    });
    markModule('battery', { status: changed === 4 ? 'installed' : changed ? 'partial' : 'native',
        detail: 'native manager; fixed profile values; trusted backend transitions suppressed; missing/fixed descriptors remain partial' });
}
