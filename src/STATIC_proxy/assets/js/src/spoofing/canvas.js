import { iterate, iterateEntries } from '../core/primordials.js';
import { numberString, invoke, slice, includes, promiseThen, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, MathIntrinsic as Math, ProxyIntrinsic as Proxy, WeakMapIntrinsic as WeakMap } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { getRuntime, markModule } from '../core/guard.js';
import { findDescriptor, replaceMethod, mapMethod } from '../core/descriptors.js';
import { createResourceBudget } from '../core/resources.js';
import { typedLength, typedKind } from '../core/primordials.js';
import { onDispose } from '../core/patches.js';
import { SetIntrinsic as Set } from '../core/primordials.js';
const imagePrototype = globalThis.ImageData?.prototype;
const imageGetters = imagePrototype ? { data: findDescriptor(imagePrototype, 'data')?.descriptor.get, width: findDescriptor(imagePrototype, 'width')?.descriptor.get, height: findDescriptor(imagePrototype, 'height')?.descriptor.get } : null;
function imageFields(image) {
    if (!imageGetters)
        return image;
    return { data: Reflect.apply(imageGetters.data, image, []), width: Reflect.apply(imageGetters.width, image, []), height: Reflect.apply(imageGetters.height, image, []) };
}
const DEFAULT_NOISE = {
    small_canvas_threshold: 16,
    small_canvas_stride: 20,
    default_stride: 10,
    noise_probability: 0.1,
    delta_min: 1,
    delta_max: 1,
    integer_delta: true,
    touch_alpha: false,
};
const CANVAS_SIGNATURE_SAMPLES = 32;
function normalizeNoiseConfig(fingerprint) {
    return {
        ...DEFAULT_NOISE,
        ...(fingerprint.canvas_noise || {}),
    };
}
function clampByte(value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return value;
}
function resolveOriginKey(runtime) {
    if (runtime.entropy?.origin) {
        return runtime.entropy.origin;
    }
    try {
        return location.origin;
    }
    catch {
        return 'opaque';
    }
}
function buildCanvasContentSignature(imageData, runtime, scopeLabel) {
    const bytes = imageData?.data;
    const width = imageData?.width || 0;
    const height = imageData?.height || 0;
    const length = bytes ? typedLength(bytes) : 0;
    if (!length || width <= 0 || height <= 0) {
        return `${scopeLabel}:${width}x${height}:empty`;
    }
    const targetSamples = Math.max(1, Math.min(CANVAS_SIGNATURE_SAMPLES, Math.floor(length / 4)));
    const stride = Math.max(4, Math.floor(length / targetSamples / 4) * 4);
    let signature = 0x811c9dc5;
    for (let index = 0; index < length; index += stride) {
        signature = runtime.entropy.hash(`${signature}:${bytes[index] || 0}:${bytes[index + 1] || 0}:${bytes[index + 2] || 0}:${bytes[index + 3] || 0}`);
    }
    const lastIndex = Math.max(0, length - 4);
    signature = runtime.entropy.hash(`${signature}:${bytes[lastIndex] || 0}:${bytes[lastIndex + 1] || 0}:${bytes[lastIndex + 2] || 0}:${bytes[lastIndex + 3] || 0}`);
    return `${scopeLabel}:${width}x${height}:${numberString(signature, 16)}`;
}
function createNoiseRng(runtime, fingerprint, imageData, seedLabel) {
    const scope = resolveOriginKey(runtime);
    const signature = buildCanvasContentSignature(imageData, runtime, `${scope}:${seedLabel}`);
    const seed = runtime.entropy.hash(`${fingerprint.canvas_hash || 'static'}:${runtime.entropy.sessionId}:${signature}`);
    return runtime.entropy.rng(seed);
}
export function injectCanvasNoise(imageData, runtime, fingerprint, noiseConfig, seedLabel = 'canvas') {
    imageData = imageFields(imageData);
    if (fingerprint.canvas_readback_mode === 'redacted') {
        const color = fingerprint.canvas_redaction_color || [0, 0, 0, 255];
        const data = imageData.data;
        const kind = typedKind(data), floating = kind !== 'Uint8ClampedArray' && kind !== 'Uint8Array';
        const length = typedLength(data);
        for (let index = 0; index < length; index++)
            data[index] = floating ? color[index % 4] / 255 : color[index % 4];
        return;
    }
    if (!imageData?.data) {
        return;
    }
    const rng = createNoiseRng(runtime, fingerprint, imageData, seedLabel);
    const configuredStride = imageData.width <= noiseConfig.small_canvas_threshold && imageData.height <= noiseConfig.small_canvas_threshold
        ? noiseConfig.small_canvas_stride
        : noiseConfig.default_stride;
    const stride = Math.max(4, Math.ceil(configuredStride / 4) * 4);
    const length = typedLength(imageData.data);
    const kind = typedKind(imageData.data), bytePixels = kind === 'Uint8ClampedArray' || kind === 'Uint8Array';
    for (let index = 0; index < length; index += stride) {
        if (!noiseConfig.touch_alpha && imageData.data[index + 3] === 0)
            continue;
        if (rng() >= noiseConfig.noise_probability) {
            continue;
        }
        const magnitude = noiseConfig.delta_min + ((noiseConfig.delta_max - noiseConfig.delta_min) * rng());
        const signed = (rng() >= 0.5 ? 1 : -1) * magnitude;
        const delta = noiseConfig.integer_delta ? Math.round(signed) : signed;
        const adjust = (value) => bytePixels ? clampByte(value + delta) : value + delta / 255;
        imageData.data[index] = adjust(imageData.data[index]);
        if (index + 1 < length) {
            imageData.data[index + 1] = adjust(imageData.data[index + 1]);
        }
        if (index + 2 < length) {
            imageData.data[index + 2] = adjust(imageData.data[index + 2]);
        }
        if (noiseConfig.touch_alpha && index + 3 < length) {
            imageData.data[index + 3] = adjust(imageData.data[index + 3]);
        }
    }
}
export function installCanvasSpoof() {
    const runtime = getRuntime(), fingerprint = getFingerprint(), noiseConfig = normalizeNoiseConfig(fingerprint);
    const budget = createResourceBudget(fingerprint.canvas_export_budget?.bytes, fingerprint.canvas_export_budget?.operations);
    const copies = new WeakMap();
    const pendingCopies = new Set();
    onDispose(() => { for (const cleanup of iterate(pendingCopies))
        cleanup(); pendingCopies.clear(); });
    const HTML = globalThis.HTMLCanvasElement, Offscreen = globalThis.OffscreenCanvas;
    const htmlProto = HTML?.prototype, offProto = Offscreen?.prototype;
    const Context = globalThis.CanvasRenderingContext2D;
    let offContextProto = globalThis.OffscreenCanvasRenderingContext2D?.prototype;
    if (!offContextProto && Offscreen) {
        try {
            const probe = new Offscreen(1, 1).getContext('2d');
            if (probe)
                offContextProto = Object.getPrototypeOf(probe);
        }
        catch { /* Optional 2D support must not abort the other canvas surfaces. */ }
    }
    const nativeRead = Context?.prototype.getImageData, offRead = offContextProto?.getImageData;
    const nativePut = Context?.prototype.putImageData, offPut = offContextProto?.putImageData;
    const create = globalThis.Document?.prototype.createElement;
    const bitmap = globalThis.createImageBitmap;
    const transfer = offProto?.transferToImageBitmap;
    const settings = new WeakMap(), attributes = Context?.prototype.getContextAttributes;
    const getContexts = new WeakMap(), dimensions = new WeakMap();
    for (const prototype of iterate([htmlProto, offProto]))
        if (prototype) {
            getContexts.set(prototype, prototype.getContext);
            dimensions.set(prototype, { width: findDescriptor(prototype, 'width')?.descriptor, height: findDescriptor(prototype, 'height')?.descriptor });
        }
    const htmlDraw = Context?.prototype.drawImage, offDraw = offContextProto?.drawImage;
    const closeBitmap = globalThis.ImageBitmap?.prototype.close;
    const close = value => { if (closeBitmap)
        Reflect.apply(closeBitmap, value, []); };
    const sizeCopy = (copy, prototype, width, height) => {
        const fields = dimensions.get(prototype);
        Reflect.apply(fields.width.set, copy, [width]);
        Reflect.apply(fields.height.set, copy, [height]);
    };
    const releaseCopy = copy => { const release = copies.get(copy); if (release) {
        copies.delete(copy);
        release();
    } };
    for (const prototype of iterate([htmlProto, offProto]))
        mapMethod(prototype, 'getContext', (context, source) => {
            if (context && attributes)
                try {
                    settings.set(source, Reflect.apply(attributes, context, []));
                }
                catch { }
            return context;
        });
    function noisyCopy(source, prototype) {
        // Native width/height accessors validate the receiver without calling an
        // export twice, and without binding the drawing surface to a new context.
        const fields = dimensions.get(prototype);
        const width = Reflect.apply(fields.width.get, source, []);
        const height = Reflect.apply(fields.height.get, source, []);
        if (!width || !height)
            return source;
        const release = budget.reserve(width, height);
        let copy;
        try {
            copy = prototype === offProto ? new Offscreen(width, height) : Reflect.apply(create, document, ['canvas']);
            sizeCopy(copy, prototype, width, height);
            const context = Reflect.apply(getContexts.get(prototype), copy, ['2d', settings.get(source)]);
            Reflect.apply(prototype === offProto ? offDraw : htmlDraw, context, [source, 0, 0]);
            const read = prototype === offProto ? offRead : nativeRead, put = prototype === offProto ? offPut : nativePut;
            const image = Reflect.apply(read, context, [0, 0, width, height, { colorSpace: settings.get(source)?.colorSpace || 'srgb' }]);
            injectCanvasNoise(image, runtime, fingerprint, noiseConfig, 'pixels');
            Reflect.apply(put, context, [image, 0, 0]);
            const cleanup = () => { pendingCopies.delete(cleanup); try {
                sizeCopy(copy, prototype, 0, 0);
            }
            finally {
                release();
            } };
            copies.set(copy, cleanup);
            pendingCopies.add(cleanup);
            return copy;
        }
        catch (error) {
            // Tainted data remains tainted: the genuine export supplies its native
            // error/rejection. Never swallow/repeat the application's export call.
            try {
                if (copy)
                    sizeCopy(copy, prototype, 0, 0);
            }
            finally {
                release();
            }
            if (error.name === 'SecurityError')
                return source;
            throw error;
        }
    }
    for (const prototype of iterate([Context?.prototype, offContextProto])) {
        mapMethod(prototype, 'getImageData', image => { injectCanvasNoise(image, runtime, fingerprint, noiseConfig, 'pixels'); return image; });
    }
    for (const [prototype, name] of iterateEntries([[htmlProto, 'toDataURL'], [htmlProto, 'toBlob'], [offProto, 'convertToBlob']])) {
        if (prototype === offProto && (!offRead || !offPut))
            continue;
        replaceMethod(prototype, name, (native, receiver, args) => {
            if (name === 'toBlob' && typeof args[0] !== 'function')
                return Reflect.apply(native, receiver, args);
            const forwarded=slice(args),mimeIndex=name==='toBlob'?1:0;
            if(name!=='convertToBlob'){
                // Validate the receiver, then DOMString MIME conversion, before
                // allocating extra copies. Quality is an `any` value here.
                Reflect.apply(dimensions.get(prototype).width.get,receiver,[]);
                if(args.length>mimeIndex&&args[mimeIndex]!==undefined)forwarded[mimeIndex]=`${args[mimeIndex]}`;
            }
            const copy = noisyCopy(receiver, prototype);
            try {
                if (name === 'toBlob')
                    return Reflect.apply(native, copy, [value => { releaseCopy(copy); args[0](value); }, ...iterate(slice(forwarded, 1))]);
                const result = Reflect.apply(native, copy, forwarded);
                if (name === 'convertToBlob')
                    return promiseThen(result, value => { releaseCopy(copy); return value; }, error => { releaseCopy(copy); throw error; });
                releaseCopy(copy);
                return result;
            }
            catch (error) {
                releaseCopy(copy);
                throw error;
            }
        });
    }
    if (transfer && offRead && offPut)
        replaceMethod(offProto, 'transferToImageBitmap', (native, source, args) => {
            const fields = dimensions.get(offProto);
            const width = Reflect.apply(fields.width.get, source, []), height = Reflect.apply(fields.height.get, source, []);
            const release = budget.reserve(width, height);
            let original, copy;
            try {
                original = Reflect.apply(native, source, args);
                copy = new Offscreen(width, height);
                const context = Reflect.apply(getContexts.get(offProto), copy, ['2d', settings.get(source)]);
                Reflect.apply(offDraw, context, [original, 0, 0]);
                const image = Reflect.apply(offRead, context, [0, 0, width, height]);
                injectCanvasNoise(image, runtime, fingerprint, noiseConfig, 'pixels');
                Reflect.apply(offPut, context, [image, 0, 0]);
                const result = Reflect.apply(transfer, copy, []);
                close(original);
                return result;
            }
            catch (error) {
                if (error.name === 'SecurityError' && original)
                    return original;
                if (original)
                    close(original);
                throw error;
            }
            finally {
                try {
                    if (copy)
                        sizeCopy(copy, offProto, 0, 0);
                }
                finally {
                    release();
                }
            }
        });
    const bitmapWidth = findDescriptor(globalThis.ImageBitmap?.prototype, 'width')?.descriptor.get;
    const bitmapHeight = findDescriptor(globalThis.ImageBitmap?.prototype, 'height')?.descriptor.get;
    if (bitmap && Offscreen && offRead && offPut && bitmapWidth && bitmapHeight)
        replaceMethod(globalThis, 'createImageBitmap', (native, receiver, args) => {
            let canvas = false;
            for (const prototype of iterate([htmlProto, offProto])) {
                const getter = prototype && dimensions.get(prototype)?.width.get;
                if (getter)
                    try {
                        Reflect.apply(getter, args[0], []);
                        canvas = true;
                        break;
                    }
                    catch { }
            }
            if (!canvas)
                return Reflect.apply(native, receiver, args);
            const attrs = settings.get(args[0]), optionsIndex = args.length <= 2 ? 1 : 5, options = args[optionsIndex], captured = {};
            const forwarded = slice(args);
            if (options && (typeof options === 'object' || typeof options === 'function'))
                forwarded[optionsIndex] = new Proxy({}, { get(_target, key) {
                        const value = Reflect.get(options, key, options);
                        if (includes(['premultiplyAlpha', 'colorSpaceConversion', 'imageOrientation', 'resizeQuality'], key) && value !== undefined) {
                            captured[key] = `${value}`;
                            return captured[key];
                        }
                        return value;
                    } });
            return promiseThen(Reflect.apply(native, receiver, forwarded), async (original) => {
                let release, copy;
                try {
                    const width = Reflect.apply(bitmapWidth, original, []), height = Reflect.apply(bitmapHeight, original, []);
                    release = budget.reserve(width, height);
                    copy = new Offscreen(width, height);
                    const context = Reflect.apply(getContexts.get(offProto), copy, ['2d', attrs]);
                    Reflect.apply(offDraw, context, [original, 0, 0]);
                    const image = Reflect.apply(offRead, context, [0, 0, width, height, { colorSpace: attrs?.colorSpace || 'srgb' }]);
                    injectCanvasNoise(image, runtime, fingerprint, noiseConfig, 'pixels');
                    Reflect.apply(offPut, context, [image, 0, 0]);
                    const result = await Reflect.apply(bitmap, receiver, [copy, { colorSpaceConversion: 'none', premultiplyAlpha: captured.premultiplyAlpha || 'default' }]);
                    close(original);
                    return result;
                }
                catch (error) {
                    if (error.name === 'SecurityError')
                        return original;
                    close(original);
                    throw error;
                }
                finally {
                    try {
                        if (copy)
                            sizeCopy(copy, offProto, 0, 0);
                    }
                    finally {
                        release?.();
                    }
                }
            });
        });
    markModule('canvas', { status: 'partial', detail: 'native readback and isolated export copies; originals never temporarily painted; color/rectangle and rendering inference require measurement' });
}
