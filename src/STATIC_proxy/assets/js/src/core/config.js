import { regexpTest, iterate, iterateEntries } from './primordials.js';
import { arrayFilter, arraySome, arrayPush, arrayJoin, stringTrim, arrayMap, stringLower, includes, stringStartsWith, arrayEvery, stringCharCodeAt, ObjectIntrinsic as Object, ArrayIntrinsic as Array, JSONIntrinsic as JSON, NumberIntrinsic as Number, StringIntrinsic as String, SetIntrinsic as Set, Uint8ArrayIntrinsic as Uint8Array } from './primordials.js';
import { getRuntime } from './guard.js';
import { copyProfile } from './primordials.js';
import { normalizeFingerprint, variantFamilies } from './schema.js';
import { resolveWebGLParameters } from './webgl-parameters.js';
import { isChromiumLike, isFirefoxLike, resolveBrowserFamily, resolveBrowserVariant } from './browser.js';
const REQUIRED_FIELDS = [
    'user_agent',
    'platform',
    'canvas_hash',
    'webgl_vendor',
    'webgl_renderer',
];
const BROWSER_VARIANT_FIELDS = ['browser_variant', 'profile_variant', 'browser_type'];
export function loadConfig(input) {
    const runtime = getRuntime();
    // Clone inputs before freezing so another realm never shares mutable persona state.
    const raw = copyProfile(input === undefined ? parseRawConfig() : input);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new TypeError('STATIC profile must be an object');
    }
    const fingerprint = raw && typeof raw.fingerprint === 'object' ? raw.fingerprint : raw;
    if (!fingerprint || Array.isArray(fingerprint)) {
        throw new TypeError('STATIC fingerprint must be an object');
    }
    const missing = arrayFilter(REQUIRED_FIELDS, (key) => !fingerprint?.[key]);
    if (!arraySome(BROWSER_VARIANT_FIELDS, (key) => fingerprint?.[key])) {
        arrayPush(missing, 'browser_variant');
    }
    if (missing.length > 0) {
        throw new TypeError(`STATIC profile missing required fields: ${arrayJoin(missing, ', ')}`);
    }
    for (const field of iterate(REQUIRED_FIELDS)) {
        if (typeof fingerprint[field] !== 'string' || !stringTrim(fingerprint[field])) {
            throw new TypeError(`STATIC profile field ${field} must be a nonempty string`);
        }
    }
    const variantValues = arrayMap(arrayFilter(BROWSER_VARIANT_FIELDS, (key) => fingerprint[key] !== undefined), (key) => stringLower(stringTrim(String(fingerprint[key]))));
    const firefoxVariants = arrayFilter(Object.keys(variantFamilies), (key) => variantFamilies[key] === 'firefox-like');
    const chromiumVariants = arrayFilter(Object.keys(variantFamilies), (key) => variantFamilies[key] === 'chromium-like');
    if (arraySome(variantValues, (value) => !includes([...iterate(firefoxVariants), ...iterate(chromiumVariants)], value)) ||
        new Set(variantValues).size !== 1) {
        throw new TypeError('STATIC browser variant is unsupported or conflicting');
    }
    const expectedFamily = includes(firefoxVariants, variantValues[0]) ? 'firefox-like' : 'chromium-like';
    for (const key of iterate(['browser_family', 'profile_family'])) {
        if (fingerprint[key] !== undefined && fingerprint[key] !== expectedFamily) {
            throw new TypeError('STATIC browser family conflicts with variant');
        }
    }
    for (const [key, value] of iterateEntries(Object.entries(fingerprint))) {
        if (stringStartsWith(key, 'enable_') && typeof value !== 'boolean') {
            throw new TypeError(`STATIC profile flag ${key} must be boolean`);
        }
    }
    for (const key of iterate(['default_stride', 'small_canvas_stride'])) {
        const value = fingerprint.canvas_noise?.[key];
        if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) {
            throw new TypeError(`STATIC canvas_noise.${key} must be a positive integer`);
        }
    }
    for (const key of iterate(['vendor', 'vendorSub', 'productSub', 'oscpu', 'buildID', 'language', 'effective_type', 'connection_type'])) {
        if (fingerprint[key] !== undefined && typeof fingerprint[key] !== 'string') {
            throw new TypeError(`STATIC ${key} must be a string`);
        }
    }
    if (fingerprint.do_not_track !== undefined && fingerprint.do_not_track !== null && typeof fingerprint.do_not_track !== 'string') {
        throw new TypeError('STATIC do_not_track must be a string or null');
    }
    if (fingerprint.languages !== undefined && !(typeof fingerprint.languages === 'string' ||
        Array.isArray(fingerprint.languages) && arrayEvery(fingerprint.languages, (value) => typeof value === 'string' && value.length))) {
        throw new TypeError('STATIC languages must contain strings');
    }
    for (const key of iterate(['hardware_concurrency', 'max_touch_points'])) {
        const value = fingerprint[key];
        if (value !== undefined && (!Number.isSafeInteger(value) || value > 0xffffffff || value < (key === 'hardware_concurrency' ? 1 : 0))) {
            throw new TypeError(`STATIC ${key} has an invalid integer range`);
        }
    }
    if (fingerprint.rtt !== undefined && (!Number.isInteger(fingerprint.rtt) || fingerprint.rtt > 0xffffffff)) {
        throw new TypeError('STATIC rtt must fit an unsigned long');
    }
    for (const key of iterate(['device_memory', 'device_pixel_ratio', 'downlink', 'rtt'])) {
        const value = fingerprint[key];
        if (value !== undefined && (!Number.isFinite(value) || value < 0 ||
            includes(['device_memory', 'device_pixel_ratio'], key) && value === 0)) {
            throw new TypeError(`STATIC ${key} has an invalid numeric range`);
        }
    }
    const uaData = fingerprint.ua_data;
    if (expectedFamily === 'chromium-like' && !uaData)
        throw new TypeError('STATIC chromium identity requires complete ua_data');
    if (uaData !== undefined) {
        if (!uaData || typeof uaData !== 'object' || Array.isArray(uaData))
            throw new TypeError('STATIC ua_data must be an object');
        for (const key of iterate(['brands', 'full_version_list'])) {
            if (uaData[key] !== undefined && !(Array.isArray(uaData[key]) && arrayEvery(uaData[key], (entry) => entry && typeof entry.brand === 'string' && typeof entry.version === 'string'))) {
                throw new TypeError(`STATIC ua_data.${key} must contain brand/version strings`);
            }
        }
        if (uaData.mobile !== undefined && typeof uaData.mobile !== 'boolean')
            throw new TypeError('STATIC ua_data.mobile must be boolean');
        for (const key of iterate(['platform', 'platform_version', 'architecture', 'bitness', 'model', 'ua_full_version'])) {
            if (uaData[key] !== undefined && typeof uaData[key] !== 'string')
                throw new TypeError(`STATIC ua_data.${key} must be a string`);
        }
    }
    if (fingerprint.media_devices !== undefined && !(Array.isArray(fingerprint.media_devices) && arrayEvery(fingerprint.media_devices, (entry) => entry && includes(['audioinput', 'audiooutput', 'videoinput'], entry.kind) &&
        (entry.label === undefined || typeof entry.label === 'string')))) {
        throw new TypeError('STATIC media_devices must contain valid kinds and string labels');
    }
    if (fingerprint.timezone !== undefined) {
        if (typeof fingerprint.timezone !== 'string')
            throw new TypeError('STATIC timezone must be a string');
        new Intl.DateTimeFormat('en-US', { timeZone: fingerprint.timezone });
    }
    for (const key of iterate(['storage_quota', 'storage_usage', 'speech_voice_limit', 'media_devices_per_kind', 'media_device_count'])) {
        const value = fingerprint[key];
        if (value !== undefined && (!Number.isSafeInteger(value) || value < (key === 'storage_usage' ? 0 : 1))) {
            throw new TypeError(`STATIC ${key} must be a safe integer in range`);
        }
    }
    for (const key of iterate(['cookie_enabled', 'save_data'])) {
        if (fingerprint[key] !== undefined && typeof fingerprint[key] !== 'boolean') {
            throw new TypeError(`STATIC ${key} must be boolean`);
        }
    }
    if (fingerprint.storage_usage !== undefined && fingerprint.storage_usage > (fingerprint.storage_quota ?? 53687091200)) {
        throw new TypeError('STATIC storage_usage exceeds persona quota');
    }
    if (fingerprint.speech_languages !== undefined && !(Array.isArray(fingerprint.speech_languages) &&
        fingerprint.speech_languages.length && arrayEvery(fingerprint.speech_languages, (value) => typeof value === 'string' && value))) {
        throw new TypeError('STATIC speech_languages must contain language strings');
    }
    if (fingerprint.speech_voices !== undefined && !(Array.isArray(fingerprint.speech_voices) && arrayEvery(fingerprint.speech_voices, (voice) => voice && typeof voice.lang === 'string' && voice.lang && arrayEvery(['name', 'voiceURI'], (key) => voice[key] === undefined || typeof voice[key] === 'string')))) {
        throw new TypeError('STATIC speech_voices must contain language and optional metadata strings');
    }
    if (fingerprint.permission_states !== undefined && (!fingerprint.permission_states ||
        typeof fingerprint.permission_states !== 'object' || Array.isArray(fingerprint.permission_states) || arraySome(Object.values(fingerprint.permission_states), (value) => !includes(['denied', 'prompt', 'native'], value)) ||
        fingerprint.permission_states.notifications !== undefined &&
            !includes(['denied', 'native'], fingerprint.permission_states.notifications))) {
        throw new TypeError('STATIC permission_states must specify denied, prompt or native; notifications denied or native');
    }
    validateCoherence(fingerprint || {});
    const contract = normalizeFingerprint(fingerprint);
    resolveWebGLParameters(fingerprint);
    if (fingerprint.audio_context?.hardware_profiles &&
        (fingerprint.audio_context.hardware_profiles.length !== 1 || fingerprint.audio_context.hardware_profiles[0].weight === 0)) {
        throw new TypeError('STATIC audio hardware pool must be resolved once before delivery');
    }
    for (const record of iterate(Object.values(fingerprint.webgl_contexts))) {
        for (const [name, value] of iterateEntries(Object.entries(record.parameters))) {
            if (Array.isArray(value) && (value.length !== 2 || name!=='MAX_VIEWPORT_DIMS'&&value[0] > value[1]))
                throw new TypeError(`STATIC invalid WebGL parameter shape ${name}`);
            if (name === 'MAX_VIEWPORT_DIMS' && arraySome(value, number => !Number.isInteger(number) || number < 0 || number > 2147483647))
                throw new TypeError('STATIC invalid viewport Int32 values');
        }
    }
    if (fingerprint.storage_usage > fingerprint.storage_quota)
        throw new TypeError('STATIC storage_usage exceeds resolved profile quota');
    if (raw.privacy_rules !== undefined) {
        if (!Array.isArray(raw.privacy_rules) || raw.privacy_rules.length > 1024)
            throw new TypeError('STATIC privacy_rules must be a bounded array');
        for (const rule of iterate(raw.privacy_rules)) {
            if (!rule || Array.isArray(rule) || typeof rule !== 'object' || arraySome(Object.keys(rule), key => !includes(['hostSuffix', 'pathPrefix'], key)) ||
                typeof rule.hostSuffix !== 'string' ||
                !regexpTest(/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i, rule.hostSuffix) ||
                (rule.pathPrefix !== undefined && (typeof rule.pathPrefix !== 'string' || !stringStartsWith(rule.pathPrefix, '/')))) {
                throw new TypeError('STATIC privacy_rules contains an invalid rule');
            }
            rule.hostSuffix = stringLower(rule.hostSuffix);
        }
    }
    runtime.config = deepFreeze({
        raw,
        fingerprint: fingerprint || {},
        ready: true,
        contract,
    });
}
function deepFreeze(value) {
    if (value && typeof value === 'object') {
        for (const child of iterate(Object.values(value)))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
function parseRawConfig() {
    const currentScript = document.currentScript;
    const encoded = currentScript?.getAttribute('data-static-config-b64');
    if (encoded) {
        currentScript.removeAttribute('data-static-config-b64');
        try {
            const bytes = Uint8Array.from(window.atob(encoded), (char) => stringCharCodeAt(char, 0));
            return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        }
        catch (error) {
            throw new TypeError('STATIC encoded profile is invalid', { cause: error });
        }
    }
    const node = document.getElementById('__static_profile');
    if (!node) {
        console.error('[STATIC] profile script tag missing');
        return {};
    }
    try {
        const text = node.textContent;
        node.remove();
        return JSON.parse(text || '{}');
    }
    catch (error) {
        throw new TypeError('STATIC profile JSON is invalid', { cause: error });
    }
}
function validateCoherence(fingerprint) {
    const ua = fingerprint.user_agent || '';
    const platform = fingerprint.platform || '';
    const vendor = fingerprint.vendor || '';
    const family = resolveBrowserFamily(fingerprint);
    const variant = resolveBrowserVariant(fingerprint);
    if (includes(ua, 'Windows') && !regexpTest(/Win/i, platform)) {
        console.warn('[STATIC] profile incoherence: UA is Windows but platform is', platform);
    }
    if (includes(ua, 'Mac OS X') && platform !== 'MacIntel') {
        console.warn('[STATIC] profile incoherence: UA is macOS but platform is', platform);
    }
    if (variant === 'chrome' && !includes(vendor, 'Google')) {
        console.warn('[STATIC] profile incoherence: chrome variant is missing a Google vendor string', vendor);
    }
    if (variant === 'edge' && includes(ua, 'Edg/') === false) {
        console.warn('[STATIC] profile incoherence: edge variant is missing Edg/ token in UA');
    }
    if (isFirefoxLike(fingerprint) && includes(ua, 'Firefox') && fingerprint.sec_ch_ua) {
        console.warn('[STATIC] profile incoherence: Firefox profile contains sec_ch_ua client hints');
    }
    if (fingerprint.browser_family && fingerprint.browser_family !== family) {
        console.warn('[STATIC] profile incoherence: browser_family does not match resolved family', fingerprint.browser_family, family);
    }
    if (fingerprint.browser_variant && fingerprint.browser_variant !== variant) {
        console.warn('[STATIC] profile incoherence: browser_variant does not match resolved variant', fingerprint.browser_variant, variant);
    }
    if (isChromiumLike(fingerprint) && !includes(ua, 'AppleWebKit/537.36')) {
        console.warn('[STATIC] profile incoherence: chromium-like profile is missing AppleWebKit token');
    }
}
export function getConfig() {
    return getRuntime().config;
}
export function getFingerprint() {
    return getRuntime().config?.fingerprint || {};
}
