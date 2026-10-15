import { iterate, iterateEntries } from '../core/primordials.js';
import { invoke, arrayMap, slice, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, MathIntrinsic as Math, NumberIntrinsic as Number, ProxyIntrinsic as Proxy } from '../core/primordials.js';
import { definePatch } from '../core/patches.js';
import { getRuntime, markModule } from '../core/guard.js';
import { getFingerprint } from '../core/config.js';
import { replaceMethod } from '../core/descriptors.js';
import { markNativeLike } from '../core/toString.js';
import { createDateModel, dateTime, NativeDateConstructor } from './date-model.js';
export function installTimezone() {
    const zone = getFingerprint().timezone;
    if (!zone) {
        markModule('timezone', { status: 'disabled' });
        return;
    }
    const Native = getRuntime().nativeRefs.intlDateTimeFormat;
    const model = createDateModel(zone, Native, getFingerprint().timezone_legacy_policy);
    const getTime = dateTime;
    replaceMethod(NativeDateConstructor.prototype, 'getTimezoneOffset', (native, receiver, args) => {
        const value = Reflect.apply(native, receiver, args);
        if (!Number.isFinite(value))
            return value;
        const instant = Reflect.apply(getTime, receiver, []);
        return model.offset(instant) / 60000;
    });
    function defaultZone(args) {
        if (args[1] === null)
            return args;
        const input = args[1] === undefined ? null : Object(args[1]);
        const options = input === null ? { timeZone: zone } : new Proxy({}, {
            get(_target, key) {
                const value = Reflect.get(input, key, input);
                return key === 'timeZone' && value === undefined ? zone : value;
            },
        });
        return [args[0], options, ...iterate(slice(args, 2))];
    }
    const wrapped = markNativeLike(new Proxy(Native, {
        apply(native, receiver, args) { return Reflect.apply(native, receiver, defaultZone(args)); },
        construct(native, args, newTarget) { return Reflect.construct(native, defaultZone(args), newTarget); },
    }), Native);
    const descriptor = Object.getOwnPropertyDescriptor(Intl, 'DateTimeFormat');
    definePatch(Intl, 'DateTimeFormat', { ...descriptor, value: wrapped });
    const constructorDescriptor = Object.getOwnPropertyDescriptor(Native.prototype, 'constructor');
    if (constructorDescriptor?.configurable) {
        definePatch(Native.prototype, 'constructor', { ...constructorDescriptor, value: wrapped });
    }
    const NativeDate = NativeDateConstructor;
    for (const suffix of iterate(['FullYear', 'Month', 'Date', 'Day', 'Hours', 'Minutes', 'Seconds', 'Milliseconds']))
        replaceMethod(NativeDate.prototype, 'get' + suffix, (native, receiver) => model.localGet(receiver, suffix));
    replaceMethod(NativeDate.prototype, 'getYear', (native, receiver) => model.localGet(receiver, 'FullYear') - 1900);
    replaceMethod(NativeDate.prototype, 'setYear', (native, receiver, args) => { Reflect.apply(getTime, receiver, []); let year = +args[0]; if (year >= 0 && year < 100)
        year = Math.trunc(year) + 1900; return model.localSet(receiver, 'FullYear', [year]); });
    for (const suffix of iterate(['FullYear', 'Month', 'Date', 'Hours', 'Minutes', 'Seconds', 'Milliseconds']))
        replaceMethod(NativeDate.prototype, 'set' + suffix, (native, receiver, args) => model.localSet(receiver, suffix, args));
    for (const [key, component] of iterateEntries([['toDateString', 'date'], ['toTimeString', 'time'], ['toString', 'both']]))
        replaceMethod(NativeDate.prototype, key, (native, receiver) => { const s = model.strings(receiver); return component === 'both' ? (s.date === 'Invalid Date' ? s.date : s.date + ' ' + s.time) : s[component]; });
    for (const key of iterate(['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString']))
        replaceMethod(NativeDate.prototype, key, (native, receiver, args) => Reflect.apply(native, receiver, defaultZone(args)));
    replaceMethod(NativeDate, 'parse', (native, receiver, args) => model.localParse(args[0]));
    const WrappedDate = markNativeLike(new Proxy(NativeDate, {
        apply() { return model.functionValue(); },
        construct(native, args, newTarget) { return model.construct(args, newTarget); }
    }), NativeDate);
    definePatch(globalThis, 'Date', { ...Object.getOwnPropertyDescriptor(globalThis, 'Date'), value: WrappedDate });
    definePatch(NativeDate.prototype, 'constructor', { ...Object.getOwnPropertyDescriptor(NativeDate.prototype, 'constructor'), value: WrappedDate });
    markModule('timezone', { status: 'partial', detail: 'profile local Date observations and default locale/Intl zone; UTC/explicit zones preserved; legacy local syntax uses explicit normalization/denial/native policy; historical engine grammar and extreme setters require browser acceptance' });
}
