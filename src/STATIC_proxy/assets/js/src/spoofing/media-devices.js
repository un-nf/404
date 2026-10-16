import { iterate } from '../core/primordials.js';
import { bind, arrayJoin, stringPadStart, numberString, arrayMap, promiseThen, arrayFilter, slice, invoke, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, ArrayIntrinsic as Array, ProxyIntrinsic as Proxy, MapIntrinsic as Map, Uint8ArrayIntrinsic as Uint8Array } from '../core/primordials.js';
import { definePatch } from '../core/patches.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, replaceMethod, mapMethod } from '../core/descriptors.js';
import { markNativeLike } from '../core/toString.js';
import { arrayFind, arraySome } from '../core/primordials.js';
import { randomValues } from '../core/primordials.js';
import { publicArray } from '../core/primordials.js';
import { onDispose } from '../core/patches.js';
export function installMediaDevicesSpoof() {
    const devices = navigator.mediaDevices;
    if (!devices) {
        markModule('mediaDevices', { status: 'unavailable' });
        return;
    }
    const fp = getFingerprint();
    // Opaque random aliases do not expose a reversible hash of a device ID. Maps
    // stay private and are used in both observation and selection directions.
    const aliases = { deviceId: new Map(), groupId: new Map() };
    const originals = { deviceId: new Map(), groupId: new Map() };
    const random = randomValues;
    if (!random)
        throw new TypeError('Media aliases require cryptographic randomness');
    let aliasBytes = 0;
    const metadata = new WeakMap(), byId = new Map();
    const nativeId = Object.getOwnPropertyDescriptor(globalThis.MediaDeviceInfo?.prototype || {}, 'deviceId')?.get;
    const nativeKind = Object.getOwnPropertyDescriptor(globalThis.MediaDeviceInfo?.prototype || {}, 'kind')?.get;
    const kindOf = device => nativeKind ? Reflect.apply(nativeKind, device, []) : device.kind;
    onDispose(() => { aliases.deviceId.clear(); aliases.groupId.clear(); originals.deviceId.clear(); originals.groupId.clear(); byId.clear(); aliasBytes = 0; });
    const nativeSettings = globalThis.MediaStreamTrack?.prototype.getSettings;
    const alias = (key, value) => {
        if (!value || value === 'default' || value === 'communications')
            return value;
        if (!aliases[key].has(value)) {
            if (aliases.deviceId.size + aliases.groupId.size >= 1024 || aliasBytes + value.length * 2 + 128 > 1048576)
                throw new DOMException('Realm media alias budget exhausted', 'QuotaExceededError');
            const bytes = random(new Uint8Array(32));
            let id = '';
            for (let index = 0; index < 32; index++)
                id += stringPadStart(numberString(bytes[index], 16), 2, '0');
            aliases[key].set(value, id);
            originals[key].set(id, value);
            aliasBytes += value.length * 2 + 128;
        }
        return aliases[key].get(value);
    };
    const unalias = (key, value) => {
        if (!value || value === 'default' || value === 'communications')
            return value;
        if (!originals[key].has(value))
            throw new DOMException('Unknown or expired realm device alias', 'OverconstrainedError');
        return originals[key].get(value);
    };
    const translate = (key, value) => {
        if (typeof value === 'string')
            return unalias(key, value);
        if (Array.isArray(value))
            return arrayMap(value, (entry) => translate(key, entry));
        if (value && typeof value === 'object')
            return new Proxy({}, { get(_target, name) {
                    const item = Reflect.get(value, name, value);
                    return name === 'exact' || name === 'ideal' ? translate(key, item) : item;
                } });
        return value;
    };
    const constraints = (value) => value && typeof value === 'object' ? new Proxy({}, {
        get(_target, key) {
            const item = Reflect.get(value, key, value);
            if (key === 'deviceId' || key === 'groupId')
                return translate(key, item);
            if ((key === 'audio' || key === 'video') && item && fp.media_devices !== undefined &&
                !arraySome(fp.media_devices, entry => entry.kind === (key === 'audio' ? 'audioinput' : 'videoinput')))
                throw new DOMException('Device kind unavailable in selected profile', 'NotFoundError');
            if (key === 'audio' || key === 'video')
                return constraints(item);
            if (key === 'advanced' && Array.isArray(item))
                return arrayMap(item, constraints);
            return item;
        },
    }) : value;
    for (const key of iterate(['deviceId', 'groupId'])) {
        replaceGetter(globalThis.MediaDeviceInfo?.prototype, key, (value) => alias(key, value));
    }
    const labels = { audioinput: 'Microphone', audiooutput: 'Speakers', videoinput: 'Camera' };
    replaceGetter(globalThis.MediaDeviceInfo?.prototype, 'label', (label, device) => {
        const kind = kindOf(device), configured = metadata.get(device) || (fp.media_devices && arrayFind(fp.media_devices, item => item.kind === kind));
        return configured?.label ?? labels[kind] ?? '';
    });
    replaceGetter(globalThis.MediaStreamTrack?.prototype, 'label', (label, track) => {
        const kind = track.kind === 'video' ? 'videoinput' : 'audioinput';
        const id = nativeSettings ? Reflect.apply(nativeSettings, track, []).deviceId : '';
        return byId.get(id)?.label ?? (fp.media_devices && arrayFind(fp.media_devices, item => item.kind === kind))?.label ?? labels[kind];
    });
    mapMethod(globalThis.MediaDeviceInfo?.prototype, 'toJSON', (result, device) => ({ ...result, deviceId: device.deviceId, groupId: device.groupId, label: device.label }));
    mapMethod(devices, 'enumerateDevices', (promise) => promiseThen(promise, (list) => {
        const counts = new Map();
        const selected = arrayFilter(list, (device) => {
            const kind = kindOf(device), count = counts.get(kind) || 0;
            counts.set(kind, count + 1);
            const entries = fp.media_devices && arrayFilter(fp.media_devices, entry => entry.kind === kind);
            const configured = entries?.length;
            const entry = entries?.[count];
            if (entry) {
                metadata.set(device, entry);
                if (nativeId) {
                    const id = Reflect.apply(nativeId, device, []);
                    if (!byId.has(id) && (byId.size >= 1024 || id.length > 4096))
                        throw new DOMException('Realm device metadata budget exhausted', 'QuotaExceededError');
                    byId.set(id, entry);
                }
            }
            return count < (fp.media_devices === undefined ? (fp.media_devices_per_kind ?? 1) : configured);
        });
        return publicArray(slice(selected, 0, fp.media_device_count ?? selected.length));
    }));
    replaceMethod(devices, 'getUserMedia', (native, receiver, args) => Reflect.apply(native, receiver, [constraints(args[0]), ...iterate(slice(args, 1))]));
    const observations = (result) => {
        // MediaTrackConstraints contains nested ConstraintSets in advanced.
        // Mask recursively on output as well as translating recursively on input.
        if (Array.isArray(result.advanced))
            result.advanced = publicArray(arrayMap(result.advanced, observations));
        for (const property of iterate(['deviceId', 'groupId'])) {
            if (typeof result[property] === 'string')
                result[property] = alias(property, result[property]);
            else if (Array.isArray(result[property]))
                result[property] = publicArray(arrayMap(result[property], (value) => alias(property, value)));
            else if (result[property] && typeof result[property] === 'object') {
                for (const constraint of iterate(['exact', 'ideal'])) {
                    const value = result[property][constraint];
                    if (typeof value === 'string')
                        result[property][constraint] = alias(property, value);
                    else if (Array.isArray(value))
                        result[property][constraint] = publicArray(arrayMap(value, (item) => alias(property, item)));
                }
            }
        }
        return result;
    };
    for (const key of iterate(['getSettings', 'getCapabilities', 'getConstraints'])) {
        mapMethod(globalThis.MediaStreamTrack?.prototype, key, observations);
    }
    mapMethod(globalThis.InputDeviceInfo?.prototype, 'getCapabilities', observations);
    replaceMethod(globalThis.MediaStreamTrack?.prototype, 'applyConstraints', (native, receiver, args) => Reflect.apply(native, receiver, args.length ? [constraints(args[0]), ...iterate(slice(args, 1))] : args));
    const sink = globalThis.HTMLMediaElement?.prototype;
    replaceGetter(sink, 'sinkId', (value) => alias('deviceId', value));
    replaceMethod(sink, 'setSinkId', (native, receiver, args) => Reflect.apply(native, receiver, args.length ? [translate('deviceId', args[0]), ...iterate(slice(args, 1))] : args));
    replaceMethod(devices, 'selectAudioOutput', (native, receiver, args) => Reflect.apply(native, receiver, args.length ? [constraints(args[0]), ...iterate(slice(args, 1))] : args));
    const AudioContext = globalThis.AudioContext;
    if (typeof AudioContext === 'function') {
        const audio = AudioContext.prototype;
        replaceGetter(audio, 'sinkId', (value) => typeof value === 'string' ? alias('deviceId', value) : value);
        replaceMethod(audio, 'setSinkId', (native, receiver, args) => Reflect.apply(native, receiver, args.length && typeof args[0] === 'string' ? [unalias('deviceId', args[0]), ...iterate(slice(args, 1))] : args));
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'AudioContext');
        if (descriptor?.writable || descriptor?.configurable) {
            const wrapped = markNativeLike(new Proxy(AudioContext, { construct(native, args, newTarget) {
                    const options = args[0];
                    const converted = options && typeof options === 'object' ? new Proxy({}, { get(_target, key) {
                            const value = Reflect.get(options, key, options);
                            return key === 'sinkId' && typeof value === 'string' ? unalias('deviceId', value) : value;
                        } }) : options;
                    return Reflect.construct(native, args.length ? [converted, ...iterate(slice(args, 1))] : args, newTarget);
                } }), AudioContext);
            definePatch(globalThis, 'AudioContext', { ...descriptor, value: wrapped });
            if (globalThis.webkitAudioContext === AudioContext) {
                const aliasDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'webkitAudioContext');
                if (aliasDescriptor?.writable || aliasDescriptor?.configurable) {
                    definePatch(globalThis, 'webkitAudioContext', { ...aliasDescriptor, value: wrapped });
                }
            }
            const constructor = Object.getOwnPropertyDescriptor(audio, 'constructor');
            if (constructor?.writable || constructor?.configurable) {
                definePatch(audio, 'constructor', { ...constructor, value: wrapped });
            }
        }
    }
    markModule('mediaDevices', { status: 'partial', detail: 'native objects with bounded inventory, opaque IDs, translated selection and settings; permission gating retained' });
}
