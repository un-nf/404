import { iterate, SymbolIntrinsic as Symbol } from '../core/primordials.js';
import { arraySome, stringEndsWith, stringStartsWith, invoke, slice, ReflectIntrinsic as Reflect, BooleanIntrinsic as Boolean, WeakMapIntrinsic as WeakMap, PromiseIntrinsic as Promise } from '../core/primordials.js';
import { getRuntime, markModule } from '../core/guard.js';
import { findDescriptor, replaceGetter, replaceMethod } from '../core/descriptors.js';
import { schedule, cancel } from '../core/primordials.js';
import { onDispose } from '../core/patches.js';
import { SetIntrinsic as Set } from '../core/primordials.js';
import { arrayPush } from '../core/primordials.js';
import { urlRecord, ArrayBufferIntrinsic as ArrayBuffer } from '../core/primordials.js';
const DEFAULT_RULES = [{ hostSuffix: 'play.google.com', pathPrefix: '/log' }];
const NativeEvent = globalThis.Event, NativeProgress = globalThis.ProgressEvent;
const dispatch = globalThis.EventTarget?.prototype.dispatchEvent;
export function matchesPrivacyRule(url, rules, base) {
    try {
        const parsed = urlRecord(url, base);
        return arraySome(rules, rule => (!rule.hostSuffix || parsed.hostname === rule.hostSuffix || stringEndsWith(parsed.hostname, '.' + rule.hostSuffix)) && (!rule.pathPrefix || stringStartsWith(parsed.pathname, rule.pathPrefix)));
    }
    catch {
        return false;
    }
}
export function installBeaconBlackhole() {
    const runtime = getRuntime(), rules = slice(DEFAULT_RULES);
    arrayPush(rules, ...iterate(slice(runtime.config.raw.privacy_rules || [])));
    const base = () => document.baseURI, Request = runtime.nativeRefs.request, Response = runtime.nativeRefs.response;
    if (runtime.nativeRefs.fetch)
        replaceMethod(window, 'fetch', (native, receiver, args) => {
            if (!args.length)
                return Reflect.apply(native, receiver, args);
            let request;
            try {
                request = new Request(args[0], args[1]);
            }
            catch (error) {
                return Promise.reject(error);
            }
            if (request.signal.aborted)
                return Promise.reject(request.signal.reason);
            if (matchesPrivacyRule(request.url, rules, base()))
                return Promise.resolve(new Response(null, { status: 204 }));
            return Reflect.apply(native, receiver, [request]);
        });
    const navigatorBrand = findDescriptor(runtime.nativeRefs.NavigatorPrototype, 'userAgent')?.descriptor.get;
    if (runtime.nativeRefs.sendBeacon)
        replaceMethod(runtime.nativeRefs.NavigatorPrototype, 'sendBeacon', (native, receiver, args) => {
            if (!args.length)
                return Reflect.apply(native, receiver, args);
            if (navigatorBrand)
                Reflect.apply(navigatorBrand, receiver, []);
            const url = urlRecord(`${args[0]}`, base()).href;
            if (!matchesPrivacyRule(url, rules, base()))
                return Reflect.apply(native, receiver, [url, ...iterate(slice(args, 1))]);
            const data = args[1], bytes = typeof data === 'string' ? new TextEncoder().encode(data).byteLength : data?.size ?? data?.byteLength ?? 0;
            return bytes <= 65536;
        });
    const prototype = runtime.nativeRefs.xhrPrototype;
    if (prototype && runtime.nativeRefs.xhrOpen && runtime.nativeRefs.xhrSend) {
        const state = new WeakMap(), brand = findDescriptor(prototype, 'readyState').descriptor.get;
        const pendingRecords = new Set();
        onDispose(() => { for (const record of iterate(pendingRecords)) {
            record.cancelled = true;
            cancel(record.timer);
        } pendingRecords.clear(); });
        const fire = (xhr, type) => {
            const event = type === 'readystatechange' || !NativeProgress ? new NativeEvent(type) : new NativeProgress(type, { lengthComputable: false, loaded: 0, total: 0 });
            return dispatch ? Reflect.apply(dispatch, xhr, [event]) : xhr.dispatchEvent(event);
        };
        for (const key of iterate(['readyState', 'status', 'statusText', 'responseURL', 'responseText', 'response']))
            replaceGetter(prototype, key, (native, xhr) => {
                const record = state.get(xhr);
                if (!record?.blocked)
                    return native;
                if (key === 'readyState')
                    return record.done ? 4 : 1;
                if (!record.done)
                    return native;
                if (key === 'status')
                    return 204;
                if (key === 'statusText')
                    return 'No Content';
                if (key === 'responseURL')
                    return record.url;
                if (key === 'responseText')
                    return '';
                if (key === 'response')
                    return xhr.responseType === 'json' || xhr.responseType === 'document' ? null :
                        xhr.responseType === 'arraybuffer' ? (record.buffer ??= new ArrayBuffer(0)) : xhr.responseType === 'blob' ? (record.blob ??= new Blob([])) : '';
                return native;
            });
        replaceMethod(prototype, 'open', (native, receiver, args) => {
            if (args.length < 2)
                return Reflect.apply(native, receiver, args);
            Reflect.apply(brand, receiver, []);
            const previous = state.get(receiver);
            if (previous) {
                previous.cancelled = true;
                cancel(previous.timer);
                pendingRecords.delete(previous);
            }
            state.delete(receiver);
            const record = { url: null, async: args.length < 3 || args[2] === undefined ? true : Boolean(args[2]), blocked: false, done: false, sent: false, cancelled: false };
            const captured = { [Symbol.toPrimitive]() {
                    record.url = urlRecord(`${args[1]}`, base()).href;
                    state.set(receiver, record);
                    return record.url;
                } };
            try {
                return Reflect.apply(native, receiver, [args[0], captured, ...iterate(slice(args, 2))]);
            }
            catch (error) {
                if (state.get(receiver) === record)
                    state.delete(receiver);
                throw error;
            }
        });
        replaceMethod(prototype, 'send', (native, receiver, args) => {
            const nativeState = Reflect.apply(brand, receiver, []), record = state.get(receiver);
            if (!record || !matchesPrivacyRule(record.url, rules, base()))
                return Reflect.apply(native, receiver, args);
            if (nativeState !== 1 || record.sent)
                throw new DOMException('XMLHttpRequest is not OPENED', 'InvalidStateError');
            if (typeof args[0] === 'symbol')
                throw new TypeError('Invalid XMLHttpRequest body');
            if (pendingRecords.size >= 1024)
                throw new DOMException('Blocked-request lifecycle budget exhausted', 'QuotaExceededError');
            record.blocked = true;
            record.sent = true;
            pendingRecords.add(record);
            const owns = () => !record.cancelled && state.get(receiver) === record;
            fire(receiver, 'loadstart');
            if (!owns())
                return;
            const finish = () => {
                if (!owns())
                    return;
                pendingRecords.delete(record);
                record.done = true;
                fire(receiver, 'readystatechange');
                if (!owns())
                    return;
                fire(receiver, 'load');
                if (!owns())
                    return;
                fire(receiver, 'loadend');
            };
            if (record.async)
                record.timer = schedule(finish, 0);
            else
                finish();
            return undefined;
        });
        replaceMethod(prototype, 'setRequestHeader', (native, receiver, args) => {
            if (state.get(receiver)?.sent)
                throw new DOMException('XMLHttpRequest send already invoked', 'InvalidStateError');
            return Reflect.apply(native, receiver, args);
        });
        replaceMethod(prototype, 'abort', (native, receiver, args) => {
            const record = state.get(receiver), pending = record?.blocked && !record.done;
            if (record) {
                record.cancelled = true;
                cancel(record.timer);
                pendingRecords.delete(record);
            }
            state.delete(receiver);
            const result = Reflect.apply(native, receiver, args);
            if (pending) {
                fire(receiver, 'abort');
                if (!state.has(receiver))
                    fire(receiver, 'loadend');
            }
            return result;
        });
    }
    markModule('beaconBlackhole', { status: 'partial', detail: 'validated fetch/abort, exact domain boundaries, native methods/receiver metadata, virtual XHR response/lifecycle without own fake slots; synthetic event trust/body-conversion limits remain explicit' });
}
