import { iterate } from '../core/primordials.js';
import { invoke, ReflectIntrinsic as Reflect, BooleanIntrinsic as Boolean, MapIntrinsic as Map } from '../core/primordials.js';
import { markModule } from '../core/guard.js';
import { replaceMethod } from '../core/descriptors.js';
import { onRollback, onDispose } from '../core/patches.js';
import { schedule as scheduleTimer, cancel } from '../core/primordials.js';
function denied() {
    return { code: 1, message: 'Geolocation denied by privacy policy', PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3 };
}
export function installGeolocationDenial() {
    const geolocation = navigator.geolocation;
    if (!geolocation)
        return;
    // Delivery of a header is not proof that this host enforces the directive.
    if (document.permissionsPolicy?.allowsFeature('geolocation') === false || document.featurePolicy?.allowsFeature('geolocation') === false) {
        markModule('geolocation', { status: 'native', detail: 'browser-enforced geolocation policy; genuine native callbacks and errors' });
        return;
    }
    const nativeClear = geolocation.clearWatch, timers = new Map();
    let nextId = 1;
    const cleanup = () => {
        for (const timer of iterate(timers.values()))
            cancel(timer);
        timers.clear();
    };
    onRollback(cleanup);
    onDispose(cleanup);
    function validate(receiver, args) {
        // clearWatch has the genuine Geolocation receiver check and never requests
        // a position. Use the reserved maximum ID only for receiver validation.
        Reflect.apply(nativeClear, receiver, [0xffffffff]);
        if (args.length < 1 || typeof args[0] !== 'function')
            throw new TypeError('Geolocation requires a success callback');
        if (args[1] != null && typeof args[1] !== 'function')
            throw new TypeError('Geolocation error callback must be callable');
        const options = args[2];
        if (options != null) {
            if (typeof options !== 'object' && typeof options !== 'function')
                throw new TypeError('Geolocation options must be a dictionary');
            // WebIDL dictionary members are observed once, in lexicographic order.
            Boolean(options.enableHighAccuracy);
            for (const key of iterate(['maximumAge', 'timeout'])) {
                const value = options[key];
                if (value !== undefined)
                    +value;
            }
        }
    }
    function schedule(receiver, args, watch) {
        validate(receiver, args);
        if (timers.size >= 1024)
            throw new DOMException('Geolocation callback resource budget exhausted', 'QuotaExceededError');
        const id = nextId++;
        const timer = scheduleTimer(() => {
            timers.delete(id);
            if (args[1])
                Reflect.apply(args[1], undefined, [denied()]);
        }, 0);
        timers.set(id, timer);
        return watch ? id : undefined;
    }
    replaceMethod(geolocation, 'getCurrentPosition', (_native, receiver, args) => schedule(receiver, args, false));
    replaceMethod(geolocation, 'watchPosition', (_native, receiver, args) => schedule(receiver, args, true));
    replaceMethod(geolocation, 'clearWatch', (native, receiver, args) => {
        Reflect.apply(native, receiver, [0xffffffff]);
        if (!args.length)
            return Reflect.apply(native, receiver, args);
        const id = (+args[0]) >>> 0;
        Reflect.apply(native, receiver, [id]);
        if (timers.has(id)) {
            cancel(timers.get(id));
            timers.delete(id);
        }
    });
    markModule('geolocation', { status: 'partial', detail: 'prototype-level JS denial where native policy is unavailable; cancellable watches and native receiver validation; error dictionary is not a native GeolocationPositionError; pre-captured methods remain outside scope' });
}
