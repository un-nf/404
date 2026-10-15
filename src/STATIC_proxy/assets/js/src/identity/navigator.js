import { iterateEntries, iterate } from '../core/primordials.js';
import { slice, arrayFilter, arrayMap, stringSplit, stringTrim, stringReplace, arrayPush, promiseThen, ObjectIntrinsic as Object, ArrayIntrinsic as Array, StringIntrinsic as String, BooleanIntrinsic as Boolean, WeakMapIntrinsic as WeakMap } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { isFirefoxLike } from '../core/browser.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, mapMethod } from '../core/descriptors.js';
import { publicArray } from '../core/primordials.js';
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
                if (hints[key] !== undefined) {
                    normalized[key] = key === 'formFactors' ? publicArray(slice(hints[key])) :
                        Array.isArray(hints[key]) ? publicArray(arrayMap(hints[key], copyBrand)) : hints[key];
                }
            }
            return normalized;
        };
        mapMethod(uaProto, 'getHighEntropyValues', (promise) => promiseThen(promise, mapResult));
        mapMethod(uaProto, 'toJSON', mapResult);
    }
    markModule('navigator', { status: unavailable.length ? 'partial' : 'installed',
        changed: Object.freeze(changed), unavailable: Object.freeze(unavailable),
        uaData: !ua ? 'unavailable' : suppressUa ? 'suppressed' : 'installed',
        detail: 'genuine identity interfaces; Chromium hints normalized, Firefox persona suppresses UA-data acquisition and neutralizes retained objects' });
}
