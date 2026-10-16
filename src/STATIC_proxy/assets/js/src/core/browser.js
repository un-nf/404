import { stringLower, stringTrim, stringSplit, StringIntrinsic as String, SetIntrinsic as Set } from './primordials.js';
const FIREFOX_LIKE = 'firefox-like';
const CHROMIUM_LIKE = 'chromium-like';
const FIREFOX_VARIANTS = new Set(['firefox', 'gecko', 'tor', 'mullvad']);
const CHROMIUM_VARIANTS = new Set(['chrome', 'chromium', 'edge', 'brave', 'vivaldi', 'opera']);
export function resolveBrowserVariant(fingerprint = {}) {
    const explicitVariant = stringLower(stringTrim(String(fingerprint.browser_variant
        || fingerprint.profile_variant
        || fingerprint.browser_type
        || '')));
    if (explicitVariant) {
        return explicitVariant;
    }
    return resolveBrowserFamily(fingerprint) === FIREFOX_LIKE ? 'firefox' : 'chrome';
}
export function resolveBrowserFamily(fingerprint = {}) {
    const explicitFamily = stringLower(stringTrim(String(fingerprint.browser_family
        || fingerprint.profile_family
        || '')));
    if (explicitFamily) {
        return explicitFamily;
    }
    const variant = stringLower(stringTrim(String(fingerprint.browser_variant || fingerprint.profile_variant || fingerprint.browser_type || '')));
    if (FIREFOX_VARIANTS.has(variant)) {
        return FIREFOX_LIKE;
    }
    if (CHROMIUM_VARIANTS.has(variant)) {
        return CHROMIUM_LIKE;
    }
    return CHROMIUM_LIKE;
}
export function isFirefoxLike(fingerprint = {}) {
    return resolveBrowserFamily(fingerprint) === FIREFOX_LIKE;
}
export function isChromiumLike(fingerprint = {}) {
    return resolveBrowserFamily(fingerprint) === CHROMIUM_LIKE;
}
export function defaultUaDataBrands(fingerprint = {}) {
    const majorVersion = stringSplit(String(fingerprint.browser_version || ''), '.')[0] || '147';
    switch (resolveBrowserVariant(fingerprint)) {
        case 'edge':
            return [
                { brand: 'Not_A Brand', version: '8' },
                { brand: 'Chromium', version: majorVersion },
                { brand: 'Microsoft Edge', version: majorVersion },
            ];
        default:
            return [
                { brand: 'Not_A Brand', version: '8' },
                { brand: 'Chromium', version: majorVersion },
                { brand: 'Google Chrome', version: majorVersion },
            ];
    }
}
