import { iterateEntries, iterate } from '../core/primordials.js';
import { slice, arrayFilter, arrayMap, stringSplit, stringTrim, stringReplace, arrayPush, promiseThen, ObjectIntrinsic as Object, ArrayIntrinsic as Array, StringIntrinsic as String, BooleanIntrinsic as Boolean, WeakMapIntrinsic as WeakMap, SetIntrinsic as Set, ReflectIntrinsic as Reflect, SymbolIntrinsic as Symbol, PromiseIntrinsic as Promise, TypeErrorIntrinsic as TypeError } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { isFirefoxLike } from '../core/browser.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, mapMethod, replaceMethod, findDescriptor } from '../core/descriptors.js';
import { publicArray } from '../core/primordials.js';
// WebIDL sequence<DOMString> conversion. These are application-owned iterables:
// honor their iterator and conversion callbacks, but do not use Array.from or
// acquire a native identity dictionary to validate them. WebIDL does not close
// the iterator when conversion of an element fails.
function requestedHints(value) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function'))
        throw new TypeError('UA-CH hints must be an iterable object');
    const method = Reflect.get(value, Symbol.iterator);
    if (typeof method !== 'function')
        throw new TypeError('UA-CH hints must be iterable');
    const iterator = Reflect.apply(method, value, []);
    if (iterator === null || (typeof iterator !== 'object' && typeof iterator !== 'function'))
        throw new TypeError('UA-CH iterator must return an object');
    const next = Reflect.get(iterator, 'next');
    const requested = new Set();
    while (true) {
        const step = Reflect.apply(next, iterator, []);
        if (step === null || (typeof step !== 'object' && typeof step !== 'function'))
            throw new TypeError('UA-CH iterator result must be an object');
        // Chromium's sequence conversion reads value before done, including
        // accessor side effects. Keep that observed order without converting
        // the terminal value (covered by the real-browser differential test).
        const hint = step.value;
        if (step.done)
            return requested;
        if (typeof hint === 'symbol')
            throw new TypeError('Cannot convert a Symbol value to a string');
        requested.add(String(hint));
    }
}
function resultField(result, key, value) {
    const descriptor = Object.create(null);
    descriptor.value = value;
    descriptor.writable = descriptor.enumerable = descriptor.configurable = true;
    Object.defineProperty(result, key, descriptor);
}
export function installNavigator() {
    const fp = getFingerprint();
    const proto = Object.getPrototypeOf(globalThis.navigator);
    const languages = publicArray(Object.freeze(Array.isArray(fp.languages) ? slice(fp.languages) : arrayFilter(arrayMap(stringSplit(String(fp.languages || fp.language || 'en-US'), ','), (x) => stringTrim(x)), Boolean)));
    const values = {
        userAgent: fp.user_agent, platform: fp.platform, vendor: fp.vendor,
        vendorSub: fp.vendorSub, productSub: fp.productSub,
        appVersion: fp.app_version ?? stringReplace(fp.user_agent, /^Mozilla\//, ''),
        hardwareConcurrency: fp.hardware_concurrency, maxTouchPoints: fp.max_touch_points,
        language: languages[0], languages, doNotTrack: fp.do_not_track,
        cookieEnabled: fp.cookie_enabled,
        oscpu: fp.oscpu, buildID: fp.buildID,
    };
    if (fp.device_memory !== undefined)
        values.deviceMemory = fp.device_memory;
    const changed = [], unavailable = [];
    for (const [name, value] of iterateEntries(Object.entries(values))) {
        if (value !== undefined)
            arrayPush((replaceGetter(proto, name, () => value) ? changed : unavailable), name);
    }
    const ua = globalThis.navigator.userAgentData;
    const suppressUa = isFirefoxLike(fp);
    if (ua) {
        // Firefox personas suppress the Chromium-only acquisition surface. Also
        // normalize any already acquired genuine object in this covered realm.
        if (suppressUa)
            replaceGetter(proto, 'userAgentData', () => undefined);
        const data = suppressUa ? { brands: [], full_version_list: [], mobile: false, platform: '', architecture: '', bitness: '', model: '', platform_version: '', ua_full_version: '', wow64: false, form_factors: [] } : fp.ua_data || {};
        const brandValues = data.brands;
        const brandArrays = new WeakMap();
        const copyBrand = (x) => ({ brand: x.brand, version: x.version });
        const mobile = data.mobile;
        const platform = data.platform;
        const hints = {
            brands: brandValues, mobile, platform, architecture: data.architecture,
            bitness: data.bitness, fullVersionList: data.full_version_list,
            model: data.model, platformVersion: data.platform_version,
            uaFullVersion: data.ua_full_version, wow64: data.wow64, formFactors: data.form_factors,
        };
        const uaProto = Object.getPrototypeOf(ua);
        const nativeBrands = findDescriptor(uaProto, 'brands')?.descriptor.get;
        replaceGetter(uaProto, 'brands', (nativeArray) => {
            if (!brandArrays.has(nativeArray))
                brandArrays.set(nativeArray, publicArray(Object.freeze(arrayMap(brandValues, copyBrand))));
            return brandArrays.get(nativeArray);
        });
        replaceGetter(uaProto, 'mobile', () => mobile);
        replaceGetter(uaProto, 'platform', () => platform);
        const mapResult = (result) => {
            const normalized = {};
            for (const key of iterate(Object.keys(result))) {
                if (Object.hasOwn(hints, key) && hints[key] !== undefined) {
                    resultField(normalized, key, key === 'formFactors' ? publicArray(slice(hints[key])) :
                        Array.isArray(hints[key]) ? publicArray(arrayMap(hints[key], copyBrand)) : hints[key]);
                }
            }
            return normalized;
        };
        // Native promise resolution can invoke Object.prototype.then on the
        // host dictionary before any downstream mapper. Never request that
        // dictionary. A captured synchronous getter supplies the genuine brand
        // check; only selected-profile copies enter promise resolution.
        replaceMethod(uaProto, 'getHighEntropyValues', (_native, receiver, args) => {
            try {
                if (typeof nativeBrands !== 'function')
                    throw new TypeError('UA-CH receiver validation is unavailable');
                Reflect.apply(nativeBrands, receiver, []);
                const requested = requestedHints(args[0]);
                return promiseThen(Promise.resolve(undefined), () => {
                    const result = {};
                    // WebIDL dictionaries expose members in lexical order.
                    for (const key of iterate(['architecture', 'bitness', 'brands', 'formFactors', 'fullVersionList', 'mobile', 'model', 'platform', 'platformVersion', 'uaFullVersion', 'wow64'])) {
                        if ((key === 'brands' || key === 'mobile' || key === 'platform' || requested.has(key)) && hints[key] !== undefined)
                            resultField(result, key, key === 'formFactors' ? publicArray(slice(hints[key])) :
                                Array.isArray(hints[key]) ? publicArray(arrayMap(hints[key], copyBrand)) : hints[key]);
                    }
                    return result;
                });
            } catch (error) {
                return Promise.reject(error);
            }
        });
        mapMethod(uaProto, 'toJSON', mapResult);
    }
    markModule('navigator', { status: unavailable.length ? 'partial' : 'installed',
        changed: Object.freeze(changed), unavailable: Object.freeze(unavailable),
        uaData: !ua ? 'unavailable' : suppressUa ? 'suppressed' : 'installed',
        detail: 'genuine identity interfaces; profile-only UA-CH dictionaries without native high-entropy acquisition; Firefox persona suppresses UA-data acquisition and neutralizes retained objects' });
}
