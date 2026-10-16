import { iterate } from '../core/primordials.js';
import { promiseThen, invoke, slice, ReflectIntrinsic as Reflect, ProxyIntrinsic as Proxy, WeakMapIntrinsic as WeakMap, SetIntrinsic as Set } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, replaceMethod } from '../core/descriptors.js';
import { suppressNativeTransitions } from '../core/events.js';
const DENIED = new Set(['notifications', 'push', 'geolocation', 'camera', 'microphone',
    'background-sync', 'clipboard-read', 'clipboard-write']);
export function permissionObservation(name, nativeState, fp) {
    const configured = fp.permission_states?.[name];
    if (configured !== undefined)
        return configured === 'native' ? nativeState : configured;
    if (name === 'persistent-storage')
        return nativeState;
    if (name === 'geolocation' && fp.enable_geolocation_spoof === false)
        return nativeState;
    return DENIED.has(name) ? 'denied' : 'prompt';
}
export function installPermissions() {
    const permissions = navigator.permissions;
    if (!permissions) {
        markModule('permissions', { status: 'unavailable' });
        return;
    }
    const fp = getFingerprint();
    const names = new WeakMap();
    const state = replaceGetter(globalThis.PermissionStatus?.prototype, 'state', (value, status) => names.has(status) ? permissionObservation(names.get(status), value, fp) : 'prompt');
    const query = state && replaceMethod(permissions, 'query', (native, receiver, args) => {
        let name;
        const descriptor = args[0];
        const converted = descriptor && (typeof descriptor === 'object' || typeof descriptor === 'function')
            ? new Proxy({}, { get(_target, key) {
                    const value = Reflect.get(descriptor, key, descriptor);
                    // Convert once during the native dictionary read; do not pre-read input.
                    if (key === 'name') {
                        name = `${value}`;
                        return name;
                    }
                    return value;
                } }) : descriptor;
        return promiseThen(Reflect.apply(native, receiver, [converted, ...iterate(slice(args, 1))]), (status) => {
            names.set(status, name);
            // Both possible backend states must map to the same profile observation.
            if (permissionObservation(name, 'granted', fp) === permissionObservation(name, 'denied', fp))
                suppressNativeTransitions(status, ['change']);
            return status;
        });
    });
    markModule('permissions', { status: query ? 'partial' : 'native',
        detail: 'profile PermissionStatus observations; trusted transitions suppressed for fixed states; real grants/operations remain distinct' });
}
