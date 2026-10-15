import { iterateEntries, iterate } from '../core/primordials.js';
import { invoke, slice, arraySome, stringLower, ReflectIntrinsic as Reflect, NumberIntrinsic as Number, MapIntrinsic as Map, WeakMapIntrinsic as WeakMap } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { findDescriptor, replaceMethod, replaceGetter } from '../core/descriptors.js';
import { resolveWebGLParameters } from '../core/webgl-parameters.js';
import { Int32ArrayIntrinsic as Int32Array, Float32ArrayIntrinsic as Float32Array } from '../core/primordials.js';
import { publicArray } from '../core/primordials.js';
export { resolveWebGLParameter } from '../core/webgl-parameters.js';
export function installWebGLSpoof() {
    const fp = getFingerprint(), precisionValues = new WeakMap();
    // Resolve every declaration before mutating any host descriptor. Extension
    // constants are not context-prototype properties.
    const configured = resolveWebGLParameters(fp);
    let installed = 0;
    for (const [kind, proto] of iterateEntries([['webgl1', globalThis.WebGLRenderingContext?.prototype], ['webgl2', globalThis.WebGL2RenderingContext?.prototype]])) {
        if (!proto)
            continue;
        const record = fp.webgl_contexts?.[kind];
        if (!record)
            throw new TypeError(`STATIC missing ${kind} observation policy`);
        const validate = findDescriptor(proto, 'getContextAttributes')?.descriptor.value;
        if (!validate)
            continue;
        const overrides = new Map([[0x1f00, record.vendor], [0x1f01, record.renderer], [0x1f02, record.version],
            [0x8b8c, record.shading_language_version], [0x9245, record.debug_vendor], [0x9246, record.debug_renderer]]);
        for (const [key, value] of iterateEntries(configured.get(kind)))
            overrides.set(key, value);
        installed += Number(replaceMethod(proto, 'getParameter', (native, receiver, args) => {
            if (!args.length)
                return Reflect.apply(native, receiver, args);
            const attributes = Reflect.apply(validate, receiver, []);
            const key = (+args[0]) >>> 0;
            // Native invalid-enum/context-loss/extension validation still applies.
            if (attributes === null || !overrides.has(key))
                return Reflect.apply(native, receiver, [key, ...iterate(slice(args, 1))]);
            const configured = overrides.get(key);
            if (key === 0x0d3a || key === 0x846d || key === 0x846e) {
                const result = key === 0x0d3a ? new Int32Array(2) : new Float32Array(2);
                result[0] = configured[0];
                result[1] = configured[1];
                return result;
            }
            return configured;
        }));
        replaceMethod(proto, 'getSupportedExtensions', (native, receiver, args) => {
            const value = Reflect.apply(native, receiver, args);
            return value === null ? null : publicArray(slice(record.extensions));
        });
        replaceMethod(proto, 'getExtension', (native, receiver, args) => {
            if (!args.length)
                return Reflect.apply(native, receiver, args);
            Reflect.apply(validate, receiver, []);
            const name = `${args[0]}`;
            // A reported inventory creates no missing implementation or GPU feature.
            if (!arraySome(record.extensions, value => stringLower(value) === stringLower(name)))
                return null;
            return Reflect.apply(native, receiver, [name, ...iterate(slice(args, 1))]);
        });
        replaceMethod(proto, 'getShaderPrecisionFormat', (native, receiver, args) => {
            if (args.length < 2)
                return Reflect.apply(native, receiver, args);
            Reflect.apply(validate, receiver, []);
            const shader = (+args[0]) >>> 0, precision = (+args[1]) >>> 0;
            const value = Reflect.apply(native, receiver, [shader, precision, ...iterate(slice(args, 2))]);
            const configured = record.shader_precision[`${shader}:${precision}`];
            if (value && configured)
                precisionValues.set(value, configured);
            return value;
        });
    }
    for (const key of iterate(['rangeMin', 'rangeMax', 'precision']))
        replaceGetter(globalThis.WebGLShaderPrecisionFormat?.prototype, key, (native, receiver) => precisionValues.get(receiver)?.[key] ?? native);
    markModule('webgl', { status: installed ? 'partial' : 'unavailable', detail: 'selected per-version metadata, exact limits, extension inventory and configured precision; actual extensions/allocations/rendering/timing remain operational exposure' });
}
