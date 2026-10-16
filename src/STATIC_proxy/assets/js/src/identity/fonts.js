import { iterate } from '../core/primordials.js';
import { bind, MathIntrinsic as Math, NumberIntrinsic as Number, WeakMapIntrinsic as WeakMap } from '../core/primordials.js';
import { getRuntime, markModule } from '../core/guard.js';
import { replaceGetter } from '../core/descriptors.js';
import { replaceMethod, findDescriptor } from '../core/descriptors.js';
import { getFingerprint } from '../core/config.js';
import { ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, SetIntrinsic as Set, stringSplit, stringTrim, stringLower, stringReplace, arrayEvery, slice } from '../core/primordials.js';
const widthDeltaCache = new WeakMap();
const heightDeltaCache = new WeakMap();
function getDelta(cache, value, runtime, axis, measurement) {
    if (!value || (typeof value !== 'object' && typeof value !== 'function')) {
        return 0;
    }
    const key = `${runtime.entropy.origin}:${runtime.entropy.sessionId}:font-metric:${axis}:${measurement}:${value.textContent || ''}`;
    const prior = cache.get(value);
    if (prior?.key === key)
        return prior.delta;
    const delta = runtime.entropy.hash(key) % 3 - 1;
    cache.set(value, { key, delta });
    return delta;
}
function perturbMetric(value, delta) {
    if (!Number.isFinite(value) || value <= 0) {
        return value;
    }
    return Math.max(0, value + delta);
}
export function installFontMetrics() {
    const runtime = getRuntime();
    if (runtime.modules.fontMetrics) {
        return;
    }
    const fp = getFingerprint(), fontPolicy = fp.font_inventory_policy || 'profile-allowlist';
    if (fontPolicy === 'profile-allowlist' && fp.fonts !== undefined && globalThis.document?.fonts) {
        const allowed = new Set();
        for (const font of iterate(fp.fonts))
            allowed.add(stringLower(font));
        for (const generic of iterate(['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui', 'ui-serif', 'ui-sans-serif', 'ui-monospace', 'ui-rounded', 'emoji', 'math', 'fangsong']))
            allowed.add(generic);
        const create = globalThis.Document?.prototype.createElement, getStyle = findDescriptor(globalThis.HTMLElement?.prototype, 'style')?.descriptor.get;
        const set = globalThis.CSSStyleDeclaration?.prototype.setProperty, get = globalThis.CSSStyleDeclaration?.prototype.getPropertyValue;
        const status = findDescriptor(Object.getPrototypeOf(document.fonts), 'status')?.descriptor.get;
        if (create && getStyle && set && get)
            replaceMethod(Object.getPrototypeOf(document.fonts), 'check', (native, receiver, args) => {
                if (!args.length)
                    return Reflect.apply(native, receiver, args);
                if (status)
                    Reflect.apply(status, receiver, []);
                const text = `${args[0]}`;
                Reflect.apply(native, receiver, [text, ...iterate(slice(args, 1))]);
                const style = Reflect.apply(getStyle, Reflect.apply(create, document, ['span']), []);
                Reflect.apply(set, style, ['font', text]);
                const family = Reflect.apply(get, style, ['font-family']);
                return !!family && arrayEvery(stringSplit(family, ','), name => allowed.has(stringLower(stringReplace(stringTrim(name), /^['"]|['"]$/g, ''))));
            });
    }
    const defineProperty = runtime.nativeRefs.defineProperty;
    markModule('fontMetrics', { status: 'partial', detail: 'order-independent metric noise; optional configured FontFaceSet.check allowlist restriction; installed glyphs/layout/canvas/SVG rendering and font loading are not emulated' });
    const getOwnPropertyDescriptor = runtime.nativeRefs.getOwnPropertyDescriptor;
    const htmlElementPrototype = runtime.nativeRefs.HTMLElementPrototype;
    if (!defineProperty || !getOwnPropertyDescriptor || !htmlElementPrototype) {
        return;
    }
    const offsetWidthDescriptor = getOwnPropertyDescriptor(htmlElementPrototype, 'offsetWidth');
    const offsetHeightDescriptor = getOwnPropertyDescriptor(htmlElementPrototype, 'offsetHeight');
    if (typeof offsetWidthDescriptor?.get !== 'function' || typeof offsetHeightDescriptor?.get !== 'function') {
        return;
    }
    replaceGetter(htmlElementPrototype, 'offsetWidth', (value, element) => perturbMetric(value, getDelta(widthDeltaCache, element, runtime, 'width', value)));
    replaceGetter(htmlElementPrototype, 'offsetHeight', (value, element) => perturbMetric(value, getDelta(heightDeltaCache, element, runtime, 'height', value)));
    markModule('fontMetrics', { status: 'partial', detail: 'order-independent metric noise; optional configured FontFaceSet.check allowlist restriction; installed glyphs/layout/canvas/SVG rendering and font loading are not emulated' });
}
