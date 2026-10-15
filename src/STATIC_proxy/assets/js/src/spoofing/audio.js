import { regexpTest, iterate } from '../core/primordials.js';
import { invoke, arrayFilter, arrayMap, stringTrim, stringLower, includes, arrayForEach, slice, promiseThen, call, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, ArrayIntrinsic as Array, MathIntrinsic as Math, NumberIntrinsic as Number, StringIntrinsic as String, BooleanIntrinsic as Boolean, ProxyIntrinsic as Proxy, WeakMapIntrinsic as WeakMap, SetIntrinsic as Set, WeakSetIntrinsic as WeakSet, Float32ArrayIntrinsic as Float32Array, Float64ArrayIntrinsic as Float64Array, clone } from '../core/primordials.js';
import { replaceGetter, replaceMethod, mapMethod, findDescriptor } from '../core/descriptors.js';
import { markNativeLike } from '../core/toString.js';
import { definePatch, patchLifetime } from '../core/patches.js';
import { withinLifetime } from '../core/lifetimes.js';
import { getFingerprint } from '../core/config.js';
import { getRuntime, markModule } from '../core/guard.js';
import { trustedEvent, eventTarget } from '../core/events.js';
import { publicArray } from '../core/primordials.js';
import { markNativeCode } from '../core/toString.js';
import { typedKind, typedLength, typedSet, ArrayBufferIntrinsic as ArrayBuffer } from '../core/primordials.js';
const wrappedPorts = new WeakSet();
const DEFAULT_AUDIO_HARDWARE_PROFILES = {
    integrated: [
        {
            id: 'integrated_realtek_interactive',
            sample_rate: 48000,
            base_frames: 256,
            output_latency: 0.0215,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 0.99999955,
                bias: 1.15e-7,
                feedback: 1.6e-7,
                modulation: 2.2e-8,
                modulation_period: 384,
                step_offset: 6.5e-8,
                step_stride: 149,
            },
        },
        {
            id: 'integrated_conexant_playback',
            sample_rate: 48000,
            base_frames: 512,
            output_latency: 0.034,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 1.00000022,
                bias: -9.5e-8,
                feedback: 2.1e-7,
                modulation: 1.8e-8,
                modulation_period: 512,
                step_offset: -5.5e-8,
                step_stride: 173,
            },
        },
    ],
    usb: [
        {
            id: 'usb_headset_48k',
            sample_rate: 48000,
            base_frames: 256,
            output_latency: 0.041,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 0.9999999,
                bias: 7.8e-8,
                feedback: 2.9e-7,
                modulation: 2.5e-8,
                modulation_period: 441,
                step_offset: 7.2e-8,
                step_stride: 131,
            },
        },
        {
            id: 'usb_codec_44k1',
            sample_rate: 44100,
            base_frames: 256,
            output_latency: 0.049,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 1.00000008,
                bias: -8.1e-8,
                feedback: 2.4e-7,
                modulation: 2.0e-8,
                modulation_period: 367,
                step_offset: -4.2e-8,
                step_stride: 157,
            },
        },
    ],
    dock: [
        {
            id: 'dock_displaylink_48k',
            sample_rate: 48000,
            base_frames: 512,
            output_latency: 0.056,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 0.99999972,
                bias: 6.4e-8,
                feedback: 3.1e-7,
                modulation: 2.9e-8,
                modulation_period: 523,
                step_offset: 8.6e-8,
                step_stride: 181,
            },
        },
    ],
    bluetooth: [
        {
            id: 'bluetooth_a2dp_48k',
            sample_rate: 48000,
            base_frames: 512,
            output_latency: 0.118,
            channel_count: 2,
            max_channel_count: 2,
            number_of_inputs: 1,
            number_of_outputs: 0,
            render: {
                gain: 1.00000012,
                bias: -6.3e-8,
                feedback: 3.6e-7,
                modulation: 3.3e-8,
                modulation_period: 613,
                step_offset: -9.1e-8,
                step_stride: 199,
            },
        },
    ],
};
const AUDIO_HARDWARE_CLASS_PATTERNS = [
    { name: 'bluetooth', pattern: /(bluetooth|airpods|buds|headphones|a2dp)/i },
    { name: 'dock', pattern: /(dock|displaylink|thunderbolt)/i },
    { name: 'usb', pattern: /(usb|headset|jabra|poly|plantronics)/i },
    { name: 'integrated', pattern: /(realtek|conexant|speakers|microphone array|intel|dell)/i },
];
function defineGetter(target, name, getter) { return replaceGetter(target, name, (value, receiver) => Reflect.apply(getter, receiver, [value])); }
function defineMethod(target, name, fn) {
    const live = patchLifetime();
    fn = markNativeLike(new Proxy(fn, { apply(native, receiver, args) { return withinLifetime(live, () => Reflect.apply(native, receiver, args)); } }), fn);
    const descriptor = Object.getOwnPropertyDescriptor(target, name);
    definePatch(target, name, {
        value: fn,
        configurable: descriptor?.configurable ?? true,
        writable: descriptor?.writable ?? true,
        enumerable: descriptor?.enumerable ?? false,
    });
}
function createScopedRng(runtime, fingerprint, label, salt = 'static') {
    const seed = runtime.entropy.hash(`${label}:${fingerprint.audio_hash || 'static'}:${salt}:${runtime.entropy.sessionId}`);
    return runtime.entropy.rng(seed);
}
function numericField(value, fallback) {
    const resolved = Number(value);
    return Number.isFinite(resolved) ? resolved : fallback;
}
function getAudioDeviceLabels(fingerprint) {
    if (!Array.isArray(fingerprint.media_devices)) {
        return [];
    }
    return arrayFilter(arrayMap(fingerprint.media_devices, (entry) => stringTrim(String(entry?.label || ''))), Boolean);
}
function classifyAudioHardware(fingerprint, audioContext) {
    const explicitClass = stringLower(stringTrim(String(audioContext.hardware_class || '')));
    if (explicitClass && DEFAULT_AUDIO_HARDWARE_PROFILES[explicitClass]) {
        return explicitClass;
    }
    const labels = getAudioDeviceLabels(fingerprint);
    for (const label of iterate(labels)) {
        for (const candidate of iterate(AUDIO_HARDWARE_CLASS_PATTERNS)) {
            if (regexpTest(candidate.pattern, label)) {
                return candidate.name;
            }
        }
    }
    return 'integrated';
}
function chooseWeightedProfile(runtime, fingerprint, profiles, label) {
    if (!Array.isArray(profiles) || profiles.length === 0) {
        return null;
    }
    const totalWeight = profiles.reduce((sum, profile) => sum + Math.max(0, numericField(profile?.weight, 1)), 0);
    if (totalWeight <= 0) {
        return profiles[0];
    }
    const rng = createScopedRng(runtime, fingerprint, 'audio-hardware', label);
    let cursor = rng() * totalWeight;
    for (const profile of iterate(profiles)) {
        const weight = Math.max(0, numericField(profile?.weight, 1));
        if (cursor <= weight) {
            return profile;
        }
        cursor -= weight;
    }
    return profiles[profiles.length - 1];
}
function resolveAudioHardwareProfile(runtime, fingerprint) {
    const audioContext = fingerprint.audio_context || {};
    const configuredProfiles = Array.isArray(audioContext.hardware_profiles)
        ? audioContext.hardware_profiles
        : null;
    if (configuredProfiles?.length) {
        return configuredProfiles[0];
    }
    const deviceClass = classifyAudioHardware(fingerprint, audioContext);
    const defaults = DEFAULT_AUDIO_HARDWARE_PROFILES[deviceClass] || DEFAULT_AUDIO_HARDWARE_PROFILES.integrated;
    return defaults[0];
}
function buildRenderModel(runtime, fingerprint, profile) {
    const configured = profile?.render || {};
    const rng = createScopedRng(runtime, fingerprint, 'audio-render', profile?.id || 'default');
    const withDrift = (base, spread) => base + ((rng() - 0.5) * spread);
    return {
        gain: withDrift(numericField(configured.gain, 1), 7.5e-7),
        bias: withDrift(numericField(configured.bias, 0), 4.0e-8),
        feedback: withDrift(numericField(configured.feedback, 2.2e-7), 7.5e-8),
        modulation: withDrift(numericField(configured.modulation, 2.0e-8), 7.5e-9),
        modulationPeriod: Math.max(97, Math.round(withDrift(numericField(configured.modulation_period ?? configured.modulationPeriod, 431), 41))),
        stepOffset: withDrift(numericField(configured.step_offset ?? configured.stepOffset, 5.0e-8), 2.5e-8),
        stepStride: Math.max(53, Math.round(withDrift(numericField(configured.step_stride ?? configured.stepStride, 149), 17))),
    };
}
export function resolveAudioPersona(runtime, fingerprint) {
    const audioContext = fingerprint.audio_context || {};
    const hardwareProfile = resolveAudioHardwareProfile(runtime, fingerprint) || {};
    const sampleRate = numericField(audioContext.sample_rate, numericField(hardwareProfile.sample_rate, 48000));
    const baseFrames = Math.max(128, Math.round(numericField(hardwareProfile.base_frames, 256)));
    const configuredBaseLatency = numericField(audioContext.base_latency, Number.NaN);
    const configuredOutputLatency = numericField(audioContext.output_latency, Number.NaN);
    const baseLatency = Number.isFinite(configuredBaseLatency) && configuredBaseLatency >= 0
        ? configuredBaseLatency
        : numericField(hardwareProfile.base_latency, baseFrames / sampleRate);
    const outputLatency = Number.isFinite(configuredOutputLatency) && configuredOutputLatency >= 0
        ? configuredOutputLatency
        : Math.max(baseLatency, numericField(hardwareProfile.output_latency, baseLatency * 2.2));
    return {
        id: String(hardwareProfile.id || 'default'),
        hardwareClass: classifyAudioHardware(fingerprint, audioContext),
        sampleRate,
        baseLatency,
        outputLatency,
        channelCount: numericField(audioContext.channel_count, numericField(hardwareProfile.channel_count, 2)),
        maxChannelCount: numericField(audioContext.max_channel_count, numericField(hardwareProfile.max_channel_count, 2)),
        numberOfInputs: numericField(audioContext.number_of_inputs, numericField(hardwareProfile.number_of_inputs, 1)),
        numberOfOutputs: numericField(audioContext.number_of_outputs, numericField(hardwareProfile.number_of_outputs, 0)),
        renderModel: buildRenderModel(runtime, fingerprint, hardwareProfile),
    };
}
function transformAudioEntry(entry, renderModel, clampToUnitRange = false) {
    if (!entry) {
        return;
    }
    let previous = 0;
    for (let index = 0, length = typedLength(entry); index < length; index += 1) {
        const original = entry[index];
        let next = (original * renderModel.gain) + renderModel.bias + (previous * renderModel.feedback);
        next += Math.sin(index / renderModel.modulationPeriod) * renderModel.modulation;
        if (index % renderModel.stepStride === 0) {
            next += renderModel.stepOffset;
        }
        previous = original;
        if (clampToUnitRange) {
            next = Math.max(-1, Math.min(1, next));
        }
        entry[index] = Math.fround(next);
    }
}
function applyAudioSignature(payload, renderModel, clampToUnitRange = false) {
    const seen = new WeakSet();
    const apply = (entry) => {
        if (!entry || typeof entry !== 'object' || seen.has(entry) ||
            !includes(['Float32Array', 'Float64Array'], typedKind(entry)))
            return;
        seen.add(entry);
        transformAudioEntry(entry, renderModel, clampToUnitRange);
    };
    if (ArrayBuffer.isView(payload)) {
        apply(payload);
        return;
    }
    if (Array.isArray(payload)) {
        arrayForEach(payload, (entry) => apply(entry));
        return;
    }
    if (Array.isArray(payload?.channelData)) {
        arrayForEach(payload.channelData, (entry) => apply(entry));
    }
}
const workletModels = new WeakMap(), messageResults = new WeakMap();
function wrapWorkletPort(runtime, fingerprint, persona, port, label) {
    if (port && !workletModels.has(port))
        workletModels.set(port, buildRenderModel(runtime, fingerprint, { id: persona.id + ':' + label, render: persona.renderModel }));
    return port;
}
function installAudioContextGetters(runtime, fingerprint, persona) {
    const owners = new WeakMap();
    const once = (prototype, key, value) => {
        const owner = findDescriptor(prototype, key)?.owner;
        if (!owner)
            return;
        const keys = owners.get(owner) || new Set();
        if (keys.has(key))
            return;
        keys.add(key);
        owners.set(owner, keys);
        replaceGetter(owner, key, () => value);
    };
    const audioPrototypes = new Set(arrayFilter([
        runtime.nativeRefs.baseAudioPrototype,
        window.AudioContext?.prototype || null,
        window.webkitAudioContext?.prototype || null,
        window.BaseAudioContext?.prototype || null,
    ], Boolean));
    if (audioPrototypes.size === 0) {
        return;
    }
    for (const prototype of iterate(audioPrototypes)) {
        const sampleRateDescriptor = Object.getOwnPropertyDescriptor(prototype, 'sampleRate');
        const baseLatencyDescriptor = Object.getOwnPropertyDescriptor(prototype, 'baseLatency');
        const outputLatencyDescriptor = Object.getOwnPropertyDescriptor(prototype, 'outputLatency');
        once(prototype, 'sampleRate', persona.sampleRate);
        once(prototype, 'baseLatency', persona.baseLatency);
        if (outputLatencyDescriptor || 'outputLatency' in prototype) {
            once(prototype, 'outputLatency', persona.outputLatency);
        }
    }
}
function installAudioDestinationGetters(runtime, persona) {
    const prototype = runtime.nativeRefs.audioDestinationPrototype;
    if (!prototype) {
        return;
    }
    const brand = findDescriptor(prototype, 'maxChannelCount')?.descriptor.get;
    const isDestination = receiver => {
        if (!brand)
            return false;
        try {
            Reflect.apply(brand, receiver, []);
            return true;
        }
        catch {
            return false;
        }
    };
    for (const key of iterate(['channelCount', 'maxChannelCount', 'numberOfInputs', 'numberOfOutputs']))
        replaceGetter(prototype, key, (native, receiver) => isDestination(receiver) ? persona[key] : native);
}
export function installAudioSpoof() {
    const runtime = getRuntime();
    const fingerprint = getFingerprint();
    if (runtime.modules.audio) {
        return;
    }
    const persona = resolveAudioPersona(runtime, fingerprint);
    // Restore the deliberately measured phase/frequency intervention. Buffer
    // perturbation alone has not demonstrated equivalent fingerprint protection.
    // Validate start() first so invalid receivers/times and repeated starts cannot
    // mutate an AudioParam. Capture genuine operations once during installation.
    const oscillatorPrototype = globalThis.OscillatorNode?.prototype;
    const frequencyGetter = findDescriptor(oscillatorPrototype, 'frequency')?.descriptor.get;
    const setFrequency = globalThis.AudioParam?.prototype.setValueAtTime;
    if (frequencyGetter && setFrequency) {
        const drift = persona.renderModel.modulation * 1.2e6 + persona.renderModel.feedback * 8.0e5;
        replaceMethod(oscillatorPrototype, 'start', (native, receiver, args) => {
            let frequency;
            try {
                frequency = Reflect.apply(frequencyGetter, receiver, []);
            }
            catch {
                return Reflect.apply(native, receiver, args);
            } // Shared source prototype.
            const when = args.length && args[0] !== undefined ? +args[0] : 0;
            const result = Reflect.apply(native, receiver, [when]);
            Reflect.apply(setFrequency, frequency, [frequency.value + drift, when]);
            return result;
        });
    }
    const rendered = new WeakSet();
    const failedBuffers = new WeakMap();
    const nativeChannels = findDescriptor(globalThis.AudioBuffer?.prototype, 'numberOfChannels')?.descriptor.get;
    const nativeChannelData = globalThis.AudioBuffer?.prototype.getChannelData;
    const maskBuffer = buffer => {
        if (buffer && !rendered.has(buffer)) {
            if (failedBuffers.has(buffer))
                throw failedBuffers.get(buffer);
            try {
                const channels = nativeChannels ? Reflect.apply(nativeChannels, buffer, []) : buffer.numberOfChannels;
                for (let channel = 0; channel < channels; channel++)
                    applyAudioSignature(nativeChannelData ? Reflect.apply(nativeChannelData, buffer, [channel]) : buffer.getChannelData(channel), persona.renderModel, true);
                rendered.add(buffer);
            }
            catch (error) {
                failedBuffers.set(buffer, error);
                throw error;
            }
        }
        return buffer;
    };
    replaceGetter(globalThis.OfflineAudioCompletionEvent?.prototype, 'renderedBuffer', maskBuffer);
    replaceGetter(globalThis.MessageEvent?.prototype, 'data', (payload, event) => {
        const model = workletModels.get(eventTarget(event));
        if (!model || !trustedEvent(event))
            return payload;
        if (!messageResults.has(event)) {
            try {
                const policy = fingerprint.audio_context?.worklet_policy || 'legacy-float-noise';
                const channels = Array.isArray(payload?.channelData) ? payload.channelData : null;
                const raw = ArrayBuffer.isView(payload) || Array.isArray(payload);
                if (!channels && policy === 'deny-opaque')
                    throw new DOMException('Opaque AudioWorklet messages are not covered', 'NotSupportedError');
                if (!channels && (!raw || policy === 'channel-data-only'))
                    return payload;
                let bytes = 0;
                for (const entry of iterate(channels || (ArrayBuffer.isView(payload) ? [payload] : payload)))
                    if (ArrayBuffer.isView(entry))
                        bytes += typedLength(entry) * 8;
                if (bytes > 1048576)
                    throw new DOMException('AudioWorklet masking budget exhausted', 'QuotaExceededError');
                const independent = entry => {
                    if (!ArrayBuffer.isView(entry))
                        return entry;
                    const kind = typedKind(entry);
                    if (kind !== 'Float32Array' && kind !== 'Float64Array')
                        return entry;
                    const result = kind === 'Float32Array' ? new Float32Array(typedLength(entry)) : new Float64Array(typedLength(entry));
                    typedSet(result, entry);
                    return result;
                };
                // Copy only recognized floating sample planes. Do not clone an
                // entire envelope, transferred native resources, control blobs
                // or SharedArrayBuffer-backed non-audio control data.
                const safeCopy = ArrayBuffer.isView(payload) ? independent(payload) : Array.isArray(payload) ? publicArray(arrayMap(payload, independent)) : { ...payload, channelData: publicArray(arrayMap(channels, independent)) };
                applyAudioSignature(safeCopy, model);
                messageResults.set(event, safeCopy);
            }
            catch (error) {
                throw error;
            }
        }
        return messageResults.get(event);
    });
    const Native = globalThis.AudioContext;
    if (typeof Native === 'function') {
        const wrapped = markNativeLike(new Proxy(Native, { construct(native, args, newTarget) {
                const options = args[0];
                const converted = options && typeof options === 'object' ? new Proxy({}, { get(_target, key) {
                        const value = Reflect.get(options, key, options);
                        return key === 'sampleRate' && value === undefined ? persona.sampleRate : value;
                    } }) : options === undefined ? { sampleRate: persona.sampleRate } : options;
                return Reflect.construct(native, [converted, ...iterate(slice(args, 1))], newTarget);
            } }), Native);
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'AudioContext');
        definePatch(globalThis, 'AudioContext', { ...descriptor, value: wrapped });
        if (globalThis.webkitAudioContext === Native) {
            const alias = Object.getOwnPropertyDescriptor(globalThis, 'webkitAudioContext');
            definePatch(globalThis, 'webkitAudioContext', { ...alias, value: wrapped });
        }
        const constructor = Object.getOwnPropertyDescriptor(Native.prototype, 'constructor');
        definePatch(Native.prototype, 'constructor', { ...constructor, value: wrapped });
    }
    if (runtime.nativeRefs.offlineStartRendering) {
        defineMethod(runtime.nativeRefs.offlineAudioPrototype, 'startRendering', markNativeCode(function startRendering() {
            return promiseThen(invoke(runtime.nativeRefs.offlineStartRendering, this, arguments), maskBuffer);
        }, 'startRendering'));
    }
    if (runtime.nativeRefs.analyserGetFloatFrequencyData) {
        const analyserModel = new WeakMap();
        let analyserCounter = 0;
        const bins = findDescriptor(runtime.nativeRefs.analyserPrototype, 'frequencyBinCount')?.descriptor.get;
        defineMethod(runtime.nativeRefs.analyserPrototype, 'getFloatFrequencyData', markNativeCode(function getFloatFrequencyData(array) {
            const result = call(runtime.nativeRefs.analyserGetFloatFrequencyData, this, array);
            let renderModel = analyserModel.get(this);
            if (!renderModel) {
                renderModel = buildRenderModel(runtime, fingerprint, {
                    id: `${persona.id}:analyser:${analyserCounter}`,
                    render: persona.renderModel,
                });
                analyserCounter += 1;
                analyserModel.set(this, renderModel);
            }
            const count = Math.min(typedLength(array), bins ? Reflect.apply(bins, this, []) : typedLength(array));
            const copy = new Float32Array(count);
            for (let index = 0; index < count; index++)
                copy[index] = array[index];
            applyAudioSignature(copy, renderModel);
            for (let index = 0; index < count; index++)
                array[index] = copy[index];
            return result;
        }, 'getFloatFrequencyData'));
    }
    const analyser = runtime.nativeRefs.analyserPrototype;
    const bins = findDescriptor(analyser, 'frequencyBinCount')?.descriptor.get, fft = findDescriptor(analyser, 'fftSize')?.descriptor.get;
    for (const name of iterate(['getFloatTimeDomainData', 'getByteFrequencyData', 'getByteTimeDomainData'])) {
        replaceMethod(analyser, name, (native, receiver, args) => {
            const result = Reflect.apply(native, receiver, args), array = args[0];
            const count = Math.min(typedLength(array), Reflect.apply(name === 'getByteFrequencyData' ? bins : fft, receiver, []));
            if (name === 'getFloatTimeDomainData') {
                const copy = new Float32Array(count);
                for (let index = 0; index < count; index++)
                    copy[index] = array[index];
                applyAudioSignature(copy, persona.renderModel, true);
                for (let index = 0; index < count; index++)
                    array[index] = copy[index];
            }
            else {
                const delta = fingerprint.audio_context?.byte_readback_delta ?? 1;
                for (let index = 0; index < count; index += persona.renderModel.stepStride)
                    array[index] = Math.max(0, Math.min(255, array[index] + delta));
            }
            return result;
        });
    }
    if (runtime.nativeRefs.audioWorkletPrototype) {
        const portDescriptor = Object.getOwnPropertyDescriptor(runtime.nativeRefs.audioWorkletPrototype, 'port');
        if (portDescriptor?.get) {
            replaceGetter(runtime.nativeRefs.audioWorkletPrototype, 'port', (port) => wrapWorkletPort(runtime, fingerprint, persona, port, 'AudioWorkletNode'));
        }
    }
    installAudioContextGetters(runtime, fingerprint, persona);
    installAudioDestinationGetters(runtime, persona);
    markModule('audio', { status: 'partial', detail: 'profile metadata and restored oscillator frequency intervention; native start validation and later automation retained; original-probe equivalence, processor realm and opaque transfer payloads remain partial' });
}
