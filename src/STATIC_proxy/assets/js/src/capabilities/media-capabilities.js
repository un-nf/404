import { iterate, iterateEntries, SymbolIntrinsic as Symbol } from '../core/primordials.js';
import { stringReplace, stringLower, arraySome, includes, slice, promiseThen, invoke, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, NumberIntrinsic as Number, StringIntrinsic as String, ProxyIntrinsic as Proxy } from '../core/primordials.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { replaceMethod } from '../core/descriptors.js';
const mimeKey = value => stringReplace(stringLower(String(value || '')), /[\s"]/g, '');
export function mediaTypeSupported(type, fp) {
    const policy = fp.media_capabilities || {};
    const key = mimeKey(type);
    return arraySome([...iterate((policy.audio_content_types || [])), ...iterate((policy.video_content_types || []))], value => mimeKey(value) === key);
}
export function mediaConfigurationSupported(configuration, fp, operation = 'decoding') {
    const policy = fp.media_capabilities || {};
    if (!configuration || !includes((policy[operation + '_types'] || []), configuration.type))
        return false;
    if (configuration.keySystemConfiguration && !includes((policy.key_systems || []), configuration.keySystemConfiguration.keySystem))
        return false;
    if (!configuration.audio && !configuration.video)
        return false;
    for (const kind of iterate(['audio', 'video'])) {
        const track = configuration[kind];
        if (!track)
            continue;
        if (!arraySome((policy[kind + '_content_types'] || []), value => mimeKey(value) === mimeKey(track.contentType)))
            return false;
        for (const [field, limit] of iterateEntries(Object.entries({ width: 'max_width', height: 'max_height', bitrate: 'max_bitrate', framerate: 'max_framerate', samplerate: 'max_sample_rate', channels: 'max_channels' }))) {
            if (track[field] !== undefined && (!Number.isFinite(Number(track[field])) || Number(track[field]) > (policy[limit] ?? 0)))
                return false;
        }
        // Optional advanced decoder properties are not silently delegated to the host.
        if (track.spatialRendering || track.hdrMetadataType || track.colorGamut && track.colorGamut !== 'srgb' || track.transferFunction && track.transferFunction !== 'srgb' || track.scalabilityMode || track.spatialScalability)
            return false;
    }
    return true;
}
export function normalizeMediaCapability(result, fp, operation = 'decoding') {
    const supported = mediaConfigurationSupported(result.configuration, fp, operation);
    // This is an advertised support policy, not a codec/DRM implementation.
    // Genuine validation, playback failures and DRM handles remain operational.
    return { ...result, supported,
        smooth: supported && (fp.media_capabilities?.smooth ?? true),
        powerEfficient: supported && (fp.media_capabilities?.power_efficient ?? true),
        ...('keySystemAccess' in result ? { keySystemAccess: supported ? result.keySystemAccess : null } : {}) };
}
export function installMediaCapabilities() {
    const capabilities = navigator.mediaCapabilities;
    const fp = getFingerprint();
    let installed = 0;
    for (const key of iterate(['decodingInfo', 'encodingInfo'])) {
        if (!capabilities)
            continue;
        installed += Number(replaceMethod(capabilities, key, (native, receiver, args) => {
            const snapshot = {};
            function dictionary(input, output) {
                if (!input || !includes(['object', 'function'], typeof input))
                    return input;
                return new Proxy({}, { get(_target, field) {
                        const value = Reflect.get(input, field, input);
                        if (includes(['audio', 'video', 'keySystemConfiguration'], field)) {
                            output[field] = value && typeof value === 'object' ? {} : value;
                            return dictionary(value, output[field]);
                        }
                        output[field] = value;
                        if (value && includes(['object', 'function'], typeof value))
                            return { [Symbol.toPrimitive](hint) {
                                    const converted = hint === 'string' ? `${value}` : +value;
                                    output[field] = converted;
                                    return converted;
                                } };
                        return value;
                    } });
            }
            const forwarded = slice(args);
            if (args.length)
                forwarded[0] = dictionary(args[0], snapshot);
            return promiseThen(Reflect.apply(native, receiver, forwarded), result => normalizeMediaCapability({ ...result, configuration: result.configuration ?? snapshot }, fp, key === 'decodingInfo' ? 'decoding' : 'encoding'));
        }));
    }
    for (const [target, key, kind] of iterateEntries([[globalThis.HTMLMediaElement?.prototype, 'canPlayType', 'element'], [globalThis.MediaSource, 'isTypeSupported', 'source']])) {
        if (!target)
            continue;
        installed += Number(replaceMethod(target, key, (native, receiver, args) => {
            if (!args.length)
                return Reflect.apply(native, receiver, args);
            let converted;
            const facade = { [Symbol.toPrimitive]() {
                    if (typeof args[0] === 'symbol')
                        throw new TypeError('Cannot convert Symbol to string');
                    converted = String(args[0]);
                    return converted;
                } };
            Reflect.apply(native, receiver, [facade, ...iterate(slice(args, 1))]);
            const supported = mediaTypeSupported(converted, fp) && (kind !== 'source' || includes((fp.media_capabilities?.decoding_types || []), 'media-source'));
            return kind === 'element' ? (supported ? 'probably' : '') : supported;
        }));
    }
    markModule('mediaCapabilities', { status: installed ? 'partial' : 'unavailable',
        detail: 'deterministic profile matrix for media capabilities, element and MediaSource probes; genuine validation/operations; WebCodecs/RTP/DRM and absent interfaces remain partial' });
}
