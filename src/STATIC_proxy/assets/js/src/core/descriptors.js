import { iterate } from './primordials.js';
import { invoke, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, ProxyIntrinsic as Proxy } from './primordials.js';
import { definePatch, skippedPatch, patchLifetime } from './patches.js';
import { markNativeLike } from './toString.js';
import { withinLifetime } from './lifetimes.js';
import { MapIntrinsic as Map, WeakMapIntrinsic as WeakMap } from './primordials.js';
const originals = new WeakMap();
function originalDescriptor(found, key) { let fields = originals.get(found.owner); if (!fields) {
    fields = new Map();
    originals.set(found.owner, fields);
} if (!fields.has(key))
    fields.set(key, { ...found.descriptor }); return fields.get(key); }
export function findDescriptor(target, key) {
    for (let owner = target; owner; owner = Object.getPrototypeOf(owner)) {
        const raw = Object.getOwnPropertyDescriptor(owner, key);
        if (raw) {
            const descriptor = Object.create(null);
            for (const field of iterate(Object.getOwnPropertyNames(raw)))
                descriptor[field] = raw[field];
            return { owner, descriptor };
        }
    }
    return null;
}
// The genuine getter performs the internal brand check before transformation.
// Preserve ownership, setters and flags; absent host APIs stay absent.
export function replaceGetter(target, key, transform) {
    const found = findDescriptor(target, key);
    if (!found?.descriptor.get || !found.descriptor.configurable) {
        skippedPatch(key);
        return false;
    }
    const original = originalDescriptor(found, key).get;
    if (typeof original !== 'function') {
        skippedPatch(key);
        return false;
    }
    const live = patchLifetime();
    const getter = markNativeLike(new Proxy(original, {
        apply(native, receiver, args) {
            live();
            return withinLifetime(live, () => {
                const value = Reflect.apply(native, receiver, args);
                // LegacyLenientThis accessors can return undefined for a bad receiver.
                return value === undefined ? value : transform(value, receiver);
            });
        },
    }), original);
    definePatch(found.owner, key, { ...found.descriptor, get: getter });
    return true;
}
export function replaceMethod(target, key, intercept) {
    const found = findDescriptor(target, key);
    if (typeof found?.descriptor.value !== 'function' ||
        (!found.descriptor.configurable && !found.descriptor.writable)) {
        skippedPatch(key);
        return false;
    }
    const original = originalDescriptor(found, key).value;
    if (typeof original !== 'function') {
        skippedPatch(key);
        return false;
    }
    const live = patchLifetime();
    const method = markNativeLike(new Proxy(original, {
        apply(native, receiver, args) { return withinLifetime(live, () => intercept(native, receiver, args)); },
    }), original);
    definePatch(found.owner, key, { ...found.descriptor, value: method });
    return true;
}
export function mapMethod(target, key, transform) {
    return replaceMethod(target, key, (native, receiver, args) => transform(Reflect.apply(native, receiver, args), receiver, args));
}
