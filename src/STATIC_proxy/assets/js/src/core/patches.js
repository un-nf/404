import { iterate } from './primordials.js';
import { arrayPush, slice, arrayReverse, SetIntrinsic as Set, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, StringIntrinsic as String } from './primordials.js';
import { functionToString, stringStartsWith } from './primordials.js';
// Realm-private patch journal. Never replace Object.defineProperty globally.
const define = Object.defineProperty;
const descriptor = Object.getOwnPropertyDescriptor;
let active = null;
const lifetimes = new Set();
const asyncPrototype = Object.getPrototypeOf(async function () { }), generatorPrototype = Object.getPrototypeOf(function* () { }), asyncGeneratorPrototype = Object.getPrototypeOf(async function* () { });
export function onRealmDispose(cleanup) { if (lifetimes.size >= 4096)
    throw new DOMException('Lifecycle resource budget exhausted', 'QuotaExceededError'); lifetimes.add({ live: true, disposal: [cleanup] }); }
export function onDispose(cleanup) {
    if (!active) {
        onRealmDispose(cleanup);
        return;
    }
    arrayPush(active.disposal, cleanup);
    onRollback(cleanup);
}
export function disposeRealm() {
    for (const journal of iterate(lifetimes)) {
        journal.live = false;
        for (const cleanup of iterate(journal.disposal))
            try {
                cleanup();
            }
            catch { }
    }
    lifetimes.clear();
}
export function patchLifetime() {
    const owner = active;
    return () => { for (let scope = owner; scope; scope = scope.parent)
        if (!scope.live)
            throw new DOMException('Protection installation disposed', 'AbortError'); };
}
function ownDescriptor(value) {
    const copy = Object.create(null);
    for (const key of iterate(['get', 'set', 'value', 'writable', 'enumerable', 'configurable']))
        if (Object.hasOwn(value, key))
            copy[key] = value[key];
    return copy;
}
export function definePatch(target, key, value) {
    const before = descriptor(target, key);
    if (active && ((!before && value.configurable !== true) ||
        (before?.configurable && value.configurable === false) ||
        (before && !before.configurable && before.writable && value.writable === false))) {
        const error = new TypeError(`Non-reversible installation: ${String(key)}`);
        arrayPush(active.errors, error);
        throw error;
    }
    try {
        const result = define(target, key, ownDescriptor(value));
        if (active)
            arrayPush(active.undo, () => before ? define(target, key, ownDescriptor(before)) : Reflect.deleteProperty(target, key));
        return result;
    }
    catch (error) {
        if (active)
            arrayPush(active.errors, error);
        throw error;
    }
}
export function skippedPatch(key) {
    if (active)
        arrayPush(active.skipped, String(key));
}
export function deletePatch(target, key) {
    const before = descriptor(target, key);
    const deleted = Reflect.deleteProperty(target, key);
    if (!deleted)
        skippedPatch(key);
    if (deleted && before && active)
        arrayPush(active.undo, () => define(target, key, ownDescriptor(before)));
    return deleted;
}
export function onRollback(cleanup) {
    if (active)
        arrayPush(active.undo, cleanup);
}
export function transaction(operation) {
    const parent = active;
    const journal = { undo: [], disposal: [], errors: [], skipped: [], live: true, parent };
    active = journal;
    try {
        const source = Reflect.apply(functionToString, operation, []);
        const prototype = Object.getPrototypeOf(operation);
        if (prototype === asyncPrototype || prototype === generatorPrototype || prototype === asyncGeneratorPrototype || stringStartsWith(source, 'async') || stringStartsWith(source, 'function*'))
            throw new TypeError('Installers must be synchronous');
        const result = operation();
        if (result && typeof result.then === 'function')
            throw new TypeError('Installers must be synchronous');
        // A legacy installer swallowing a define failure cannot claim success.
        if (journal.errors.length)
            throw journal.errors[0];
        if (parent) {
            arrayPush(parent.undo, ...iterate(journal.undo));
            arrayPush(parent.skipped, ...iterate(journal.skipped));
            arrayPush(parent.disposal, ...iterate(journal.disposal));
        }
        else
            lifetimes.add(journal);
        return { changed: journal.undo.length, skipped: slice(journal.skipped) };
    }
    catch (error) {
        journal.live = false;
        const rollbackErrors = [];
        for (const undo of iterate(arrayReverse(journal.undo))) {
            try {
                undo();
            }
            catch (failure) {
                arrayPush(rollbackErrors, String(failure.message || failure));
            }
        }
        const failure = new Error(String(error?.message || error));
        failure.name = error?.name || 'Error';
        failure.rollbackErrors = rollbackErrors;
        throw failure;
    }
    finally {
        active = parent;
    }
}
