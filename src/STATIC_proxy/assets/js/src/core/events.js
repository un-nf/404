import { iterateEntries, iterate } from './primordials.js';
import { invoke, ReflectIntrinsic as Reflect, WeakMapIntrinsic as WeakMap, SetIntrinsic as Set } from './primordials.js';
import { onRollback, onRealmDispose } from './patches.js';
import { MapIntrinsic as Map } from './primordials.js';
import { ObjectIntrinsic as Object } from './primordials.js';
const nativeTrusted = globalThis.Event && (Object.getOwnPropertyDescriptor(Event.prototype, 'isTrusted')?.get || Object.getOwnPropertyDescriptor(new Event(''), 'isTrusted')?.get);
const nativeTarget = globalThis.Event && Object.getOwnPropertyDescriptor(Event.prototype, 'target')?.get;
export const trustedEvent = event => nativeTrusted ? Reflect.apply(nativeTrusted, event, []) : event.isTrusted === true;
export const eventTarget = event => nativeTarget ? Reflect.apply(nativeTarget, event, []) : event.target;
const add = globalThis.EventTarget?.prototype.addEventListener;
const remove = globalThis.EventTarget?.prototype.removeEventListener;
const stop = globalThis.Event?.prototype.stopImmediatePropagation;
const observed = new WeakMap();
const NativeWeakRef = globalThis.WeakRef, deref = NativeWeakRef?.prototype.deref, registrations = new Map();
let nextRegistration = 0, disposalInstalled = false;
function transitionListener(reference, selfOnly) {
    return event => {
        const target = selfOnly ? (deref ? Reflect.apply(deref, reference, []) : reference) : undefined;
        if (trustedEvent(event) && (!selfOnly || eventTarget(event) === target))
            Reflect.apply(stop, event, []);
    };
}
// Constant profile observations do not transition when native state changes.
// Keep application-dispatched events and native registration/removal semantics.
export function suppressNativeTransitions(target, types, selfOnly = false) {
    if (!add || !remove || !stop)
        return false;
    if (!disposalInstalled) {
        onRealmDispose(() => { for (const [id, record] of iterateEntries(registrations)) {
            const value = deref ? Reflect.apply(deref, record.reference, []) : record.reference;
            if (value)
                Reflect.apply(remove, value, [record.type, record.listener, true]);
        } registrations.clear(); disposalInstalled = false; });
        disposalInstalled = true;
    }
    let installed = observed.get(target);
    if (!installed) {
        installed = new Set();
        observed.set(target, installed);
    }
    for (const type of iterate(types)) {
        if (installed.has(type))
            continue;
        // Prune dead weak registrations before applying a bounded live budget.
        for (const [id, record] of iterateEntries(registrations))
            if (deref && !Reflect.apply(deref, record.reference, []))
                registrations.delete(id);
        if (registrations.size >= 4096)
            throw new DOMException('Event suppression resource budget exhausted', 'QuotaExceededError');
        const reference = NativeWeakRef ? new NativeWeakRef(target) : target;
        const listener = transitionListener(reference, selfOnly);
        Reflect.apply(add, target, [type, listener, true]);
        installed.add(type);
        const id = nextRegistration++;
        registrations.set(id, { reference, type, listener });
        onRollback(() => { Reflect.apply(remove, target, [type, listener, true]); installed.delete(type); registrations.delete(id); });
    }
    return true;
}
