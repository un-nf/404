import { iterateEntries } from '../core/primordials.js';
import { arrayMap, stringSplit, ObjectIntrinsic as Object, MathIntrinsic as Math, NumberIntrinsic as Number } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { suppressNativeTransitions } from '../core/events.js';
import { replaceGetter } from '../core/descriptors.js';
function defineScreenGetter(name, fn) {
    return replaceGetter(Screen.prototype, name, () => fn());
}
function parseResolution(value) {
    const [width, height] = arrayMap(stringSplit(value, 'x'), Number);
    return { width, height };
}
export function installScreen() {
    const fingerprint = getFingerprint();
    const resolution = parseResolution(fingerprint.screen_resolution);
    defineScreenGetter('width', () => resolution.width);
    defineScreenGetter('height', () => resolution.height);
    defineScreenGetter('availWidth', () => fingerprint.screen_avail_width ?? resolution.width);
    defineScreenGetter('availHeight', () => fingerprint.screen_avail_height ?? (resolution.height - 40));
    defineScreenGetter('availTop', () => fingerprint.screen_avail_top ?? 0);
    defineScreenGetter('availLeft', () => fingerprint.screen_avail_left ?? 0);
    defineScreenGetter('colorDepth', () => fingerprint.color_depth ?? 24);
    defineScreenGetter('pixelDepth', () => fingerprint.pixel_depth ?? fingerprint.color_depth ?? 24);
    defineScreenGetter('isExtended', () => fingerprint.screen_is_extended ?? false);
    if (screen.orientation) {
        const proto = Object.getPrototypeOf(screen.orientation);
        replaceGetter(proto, 'type', () => fingerprint.screen_orientation_type || 'landscape-primary');
        replaceGetter(proto, 'angle', () => fingerprint.screen_orientation_angle ?? 0);
        suppressNativeTransitions(screen.orientation, ['change']);
    }
    replaceGetter(window, 'devicePixelRatio', () => fingerprint.device_pixel_ratio ?? 1);
    if (fingerprint.enable_viewport_spoof) {
        for (const [key, field] of iterateEntries(Object.entries({ innerWidth: 'window_inner_width', innerHeight: 'window_inner_height',
            outerWidth: 'window_outer_width', outerHeight: 'window_outer_height' }))) {
            replaceGetter(window, key, (native) => fingerprint[field] ??
                Math.round(native / (fingerprint.viewport_rounding || 1)) * (fingerprint.viewport_rounding || 1));
        }
    }
    markModule('screen', { status: 'partial', detail: 'screen and configured viewport observations; actual CSS/layout/viewport sizing remains browser-controlled' });
}
