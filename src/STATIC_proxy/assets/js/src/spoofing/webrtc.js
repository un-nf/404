import { iterate, iterateEntries, SymbolIntrinsic as Symbol } from '../core/primordials.js';
import { stringTrim, stringStartsWith, slice, stringSplit, includes, arrayJoin, arrayMap, arrayFilter, invoke, promiseThen, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, MathIntrinsic as Math, NumberIntrinsic as Number, StringIntrinsic as String, ProxyIntrinsic as Proxy, MapIntrinsic as Map, WeakMapIntrinsic as WeakMap, WeakSetIntrinsic as WeakSet, NativeMapPrototype } from '../core/primordials.js';
import { findDescriptor, replaceGetter, replaceMethod, mapMethod } from '../core/descriptors.js';
import { definePatch, transaction, onDispose } from '../core/patches.js';
import { getFingerprint } from '../core/config.js';
import { getRuntime, markModule } from '../core/guard.js';
import { markNativeCode, markNativeLike } from '../core/toString.js';
import { createTranslationStore } from '../core/translations.js';
import { PromiseIntrinsic as Promise } from '../core/primordials.js';
const PRIVATE_IPV4 = /^(0\.|10\.|127\.|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)/;
const PRIVATE_IPV6 = /^(::1|fc00:|fd00:|fe80:)/i;
const originalOnIceCandidateHandlers = new WeakMap();
const wrappedOnIceCandidateHandlers = new WeakMap();
const candidateFields = Object.create(null), descriptionFields = Object.create(null);
for (const key of iterate(['candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment']))
    candidateFields[key] = findDescriptor(globalThis.RTCIceCandidate?.prototype, key)?.descriptor.get;
for (const key of iterate(['sdp', 'type']))
    descriptionFields[key] = findDescriptor(globalThis.RTCSessionDescription?.prototype, key)?.descriptor.get;
const field = (value, key, fields) => { if (fields[key])
    try {
        return Reflect.apply(fields[key], value, []);
    }
    catch { } return value[key]; };
function defineMethod(target, name, fn) {
    const descriptor = Object.getOwnPropertyDescriptor(target, name);
    definePatch(target, name, {
        value: fn,
        configurable: descriptor?.configurable ?? true,
        writable: descriptor?.writable ?? true,
        enumerable: descriptor?.enumerable ?? false,
    });
}
export function sanitizeCandidateLine(line, fingerprint) {
    if (typeof line !== 'string') {
        return line;
    }
    const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '192.0.2.1';
    const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:db8::1';
    const trimmed = stringTrim(line);
    const prefixed = stringStartsWith(trimmed, 'a=');
    const payload = prefixed ? slice(trimmed, 2) : trimmed;
    const parts = stringSplit(payload, /\s+/);
    if (parts.length < 8) {
        return trimmed;
    }
    const ipIndex = 4;
    const preserveRelay = fingerprint.webrtc_observation_policy === 'preserve-relay-routing' && parts[6] === 'typ' && parts[7] === 'relay';
    if (!preserveRelay)
        parts[ipIndex] = includes(parts[ipIndex], ':') ? publicIpv6 : publicIpv4;
    for (let index = 8; index < parts.length - 1; index++)
        if (parts[index] === 'raddr')
            parts[index + 1] = includes(parts[index + 1], ':') ? publicIpv6 : publicIpv4;
    const nextLine = arrayJoin(parts, ' ');
    return prefixed ? `a=${nextLine}` : nextLine;
}
function sanitizeSessionDescription(runtime, description, fingerprint) {
    if (!description)
        return description;
    const sdp = field(description, 'sdp', descriptionFields), type = field(description, 'type', descriptionFields);
    if (!sdp) {
        return description;
    }
    const candidateLimit = Math.max(1, Number(fingerprint.webrtc_candidate_limit) || 4);
    let candidates = 0;
    const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '192.0.2.1';
    const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:db8::1';
    const sanitized = arrayJoin(arrayMap(arrayFilter(stringSplit(String(sdp), /\r?\n/), (line) => {
        if (!stringStartsWith(line, 'a=candidate')) {
            return true;
        }
        candidates += 1;
        return candidates <= candidateLimit;
    }), (line) => {
        if (stringStartsWith(line, 'a=candidate')) {
            return sanitizeCandidateLine(line, fingerprint);
        }
        if (stringStartsWith(line, 'c=IN IP4')) {
            return `c=IN IP4 ${publicIpv4}`;
        }
        if (stringStartsWith(line, 'c=IN IP6')) {
            return `c=IN IP6 ${publicIpv6}`;
        }
        if (stringStartsWith(line, 'o=')) {
            const parts = stringSplit(line, /\s+/);
            if (parts.length >= 6 && (parts[4] === 'IP4' || parts[4] === 'IP6')) {
                parts[5] = parts[4] === 'IP6' ? publicIpv6 : publicIpv4;
                return arrayJoin(parts, ' ');
            }
        }
        return line;
    }), '\r\n');
    if (sanitized === sdp) {
        return description;
    }
    if (typeof runtime.nativeRefs.RTCSessionDescription === 'function') {
        try {
            return new runtime.nativeRefs.RTCSessionDescription({ type, sdp: sanitized });
        }
        catch {
            // ignore
        }
    }
    return { type, sdp: sanitized };
}
function sanitizeIceCandidate(runtime, candidate, fingerprint) {
    if (!candidate)
        return candidate;
    const text = field(candidate, 'candidate', candidateFields);
    if (typeof text !== 'string') {
        return candidate;
    }
    const sanitizedLine = sanitizeCandidateLine(text, fingerprint);
    if (!sanitizedLine || sanitizedLine === text) {
        return candidate;
    }
    if (typeof runtime.nativeRefs.RTCIceCandidate === 'function') {
        try {
            return new runtime.nativeRefs.RTCIceCandidate({
                candidate: sanitizedLine,
                sdpMid: field(candidate, 'sdpMid', candidateFields) || null,
                sdpMLineIndex: field(candidate, 'sdpMLineIndex', candidateFields),
                usernameFragment: field(candidate, 'usernameFragment', candidateFields),
            });
        }
        catch {
            // ignore
        }
    }
    throw new DOMException('Branded candidate masking unavailable','NotSupportedError');
}
export function installWebRTCSpoof() {
    const runtime = getRuntime(), fingerprint = getFingerprint(), proto = runtime.nativeRefs.peerPrototype;
    if (!proto) {
        markModule('webrtc', { status: 'unavailable' });
        return;
    }
    if (fingerprint.webrtc_transport_policy === 'relay-only') {
        const enforce = config => config == null ? { iceTransportPolicy: 'relay' } : new Proxy({}, { get(_target, key) {
                const value = Reflect.get(config, key, config);
                if (key === 'iceTransportPolicy') {
                    if (value !== undefined && !includes(['all', 'relay'], `${value}`))
                        throw new TypeError('Invalid iceTransportPolicy');
                    return 'relay';
                }
                return value;
            } });
        const Native = runtime.nativeRefs.RTCPeerConnection;
        const Wrapped = markNativeLike(new Proxy(Native, { construct(native, args, newTarget) {
                const config = args[0];
                if (config != null && !includes(['object', 'function'], typeof config))
                    return Reflect.construct(native, args, newTarget);
                return Reflect.construct(native, [enforce(config), ...iterate(slice(args, 1))], newTarget);
            } }), Native);
        for (const name of iterate(['RTCPeerConnection', 'webkitRTCPeerConnection']))
            if (globalThis[name] === Native)
                definePatch(globalThis, name, { ...Object.getOwnPropertyDescriptor(globalThis, name), value: Wrapped });
        definePatch(proto, 'constructor', { ...Object.getOwnPropertyDescriptor(proto, 'constructor'), value: Wrapped });
        replaceMethod(proto, 'setConfiguration', (native, receiver, args) => {
            if (!args.length || args[0] != null && !includes(['object', 'function'], typeof args[0]))
                return Reflect.apply(native, receiver, args);
            return Reflect.apply(native, receiver, [enforce(args[0]), ...iterate(slice(args, 1))]);
        });
    }
    const translations = createTranslationStore();
    onDispose(() => translations.dispose());
    const candidateObjects = new WeakMap(), descriptionObjects = new WeakMap();
    const reports = new WeakSet(), values = new WeakMap(), iterators = new WeakMap(), reportPrototypes = new WeakSet(), iteratorPrototypes = new WeakSet();
    const maskStats = value => {
        if (!value || typeof value !== 'object')
            return value;
        if (!values.has(value)) {
            const descriptors = Object.getOwnPropertyDescriptors(value);
            for (const key of iterate(['address', 'ip', 'ipAddress', 'relatedAddress'])) {
                const field = descriptors[key];
                if (typeof field?.value === 'string' && field.value)
                    field.value = includes(field.value, ':') ? (fingerprint.webrtc_ipv6 || '2001:db8::1') : (fingerprint.webrtc_ip || fingerprint.ip_address || '192.0.2.1');
            }
            values.set(value, Object.create(Object.getPrototypeOf(value), descriptors));
        }
        return values.get(value);
    };
    function wrapIterator(iterator, mode) {
        iterators.set(iterator, mode);
        const prototype = Object.getPrototypeOf(iterator);
        if (!iteratorPrototypes.has(prototype)) {
            if (!mapMethod(prototype, 'next', (step, receiver) => {
                const kind = iterators.get(receiver);
                if (kind && !step.done)
                    step.value = kind === 'entries' ? [step.value[0], maskStats(step.value[1])] : maskStats(step.value);
                return step;
            }))
                throw new DOMException('Stats iterator masking unavailable', 'NotSupportedError');
            iteratorPrototypes.add(prototype);
        }
        return iterator;
    }
    function shieldReportPrototype(prototype) {
        if (!reportPrototypes.has(prototype)) {
            transaction(() => {
                const symbol = findDescriptor(prototype, Symbol.iterator), entry = findDescriptor(prototype, 'entries');
                if (!mapMethod(prototype, 'get', (value, receiver) => reports.has(receiver) ? maskStats(value) : value))
                    throw new DOMException('Stats masking unavailable', 'NotSupportedError');
                for (const kind of iterate(['entries', 'values']))
                    if (!mapMethod(prototype, kind, (iterator, receiver) => reports.has(receiver) ? wrapIterator(iterator, kind) : iterator))
                        throw new DOMException('Stats iteration masking unavailable', 'NotSupportedError');
                if (symbol?.descriptor.value === entry?.descriptor.value)
                    definePatch(symbol.owner, Symbol.iterator, { ...symbol.descriptor, value: findDescriptor(prototype, 'entries').descriptor.value });
                else if (!mapMethod(prototype, Symbol.iterator, (iterator, receiver) => reports.has(receiver) ? wrapIterator(iterator, 'entries') : iterator))
                    throw new DOMException('Stats iteration masking unavailable', 'NotSupportedError');
                if (!replaceMethod(prototype, 'forEach', (native, receiver, args) => {
                    if (!reports.has(receiver) || typeof args[0] !== 'function')
                        return Reflect.apply(native, receiver, args);
                    return Reflect.apply(native, receiver, [(value, key, collection) => Reflect.apply(args[0], args[1], [maskStats(value), key, collection])]);
                }))
                    throw new DOMException('Stats callback masking unavailable', 'NotSupportedError');
            });
            reportPrototypes.add(prototype);
        }
    }
    shieldReportPrototype(NativeMapPrototype);
    if (globalThis.RTCStatsReport?.prototype)
        shieldReportPrototype(RTCStatsReport.prototype);
    wrapIterator(invoke(NativeMapPrototype.entries, new Map(), []), 'entries');
    for (const target of iterate([proto, globalThis.RTCRtpSender?.prototype, globalThis.RTCRtpReceiver?.prototype]))
        if (target)
            mapMethod(target, 'getStats', promise => promiseThen(promise, report => {
                shieldReportPrototype(Object.getPrototypeOf(report));
                reports.add(report);
                return report;
            }));
    function maskDescription(value, peer, generation, reversible = true) {
        if (!value)
            return value;
        const sdp = field(value, 'sdp', descriptionFields), type = field(value, 'type', descriptionFields);
        if (typeof sdp !== 'string')
            return value;
        const masked = sanitizeSessionDescription(runtime, value, fingerprint).sdp;
        const result = { ...value, type, sdp: masked };
        if (reversible)
            translations.record(peer, generation, result, type, masked, sdp);
        return result;
    }
    replaceGetter(globalThis.RTCPeerConnectionIceEvent?.prototype, 'candidate', candidate => {
        if (!candidate)
            return candidate;
        if (!candidateObjects.has(candidate)) {
            const masked = sanitizeIceCandidate(runtime, candidate, fingerprint);
            candidateObjects.set(candidate, masked);
        }
        return candidateObjects.get(candidate);
    });
    for (const name of iterate(['createOffer', 'createAnswer']))
        replaceMethod(proto, name, (native, peer, args) => {
            const generation = translations.generation(peer);
            return promiseThen(Reflect.apply(native, peer, args), value => maskDescription(value, peer, generation));
        });
    for (const name of iterate(['localDescription', 'remoteDescription', 'currentLocalDescription', 'pendingLocalDescription', 'currentRemoteDescription', 'pendingRemoteDescription'])) {
        replaceGetter(proto, name, (value, peer) => {
            if (!value)
                return value;
            let cache=descriptionObjects.get(peer);if(!cache){cache=new WeakMap();descriptionObjects.set(peer,cache);}
            if (!cache.has(value)) {
                const generation=translations.generation(peer),local=name.indexOf('Remote')<0&&name!=='remoteDescription';
                const masked = maskDescription(value, peer, generation, local);
                if(typeof runtime.nativeRefs.RTCSessionDescription!=='function')throw new DOMException('Branded description masking unavailable','NotSupportedError');
                const exposed=new runtime.nativeRefs.RTCSessionDescription(masked);
                if(local)translations.record(peer,generation,exposed,masked.type,masked.sdp,field(value,'sdp',descriptionFields));
                cache.set(value,exposed);
            }
            return cache.get(value);
        });
    }
    for (const [name, key] of iterateEntries([['setLocalDescription', 'sdp'], ['setRemoteDescription', 'sdp'], ['addIceCandidate', 'candidate']])) {
        replaceMethod(proto, name, (native, receiver, args) => {
            const input = args[0];
            if (name === 'setLocalDescription' && input !== null && input !== undefined && (typeof input === 'object' || typeof input === 'function')) {
                const brand = findDescriptor(proto, 'signalingState')?.descriptor.get;
                if (brand)
                    try {
                        Reflect.apply(brand, receiver, []);
                    }
                    catch {
                        return Reflect.apply(native, receiver, args);
                    }
                // WebIDL dictionaries convert members in lexicographic order:
                // sdp before type. Snapshot/coerce once, then reverse with the
                // owning connection/type; never re-read a user getter.
                try {
                    const rawSDP = Reflect.get(input, 'sdp', input), sdp = rawSDP === undefined ? '' : `${rawSDP}`;
                    const rawType = Reflect.get(input, 'type', input), type = rawType === undefined ? undefined : `${rawType}`;
                    const converted = { sdp: type === 'rollback' || !sdp ? sdp : translations.reverse(receiver, input, type, sdp) };
                    if (type !== undefined)
                        converted.type = type;
                    const result = Reflect.apply(native, receiver, [converted, ...iterate(slice(args, 1))]);
                    return type === 'rollback' ? promiseThen(result, value => { translations.reset(receiver); return value; }) : result;
                }
                catch (error) {
                    return Promise.reject(error);
                }
            }
            let convertedType;
            const translated = input && typeof input === 'object' ? new Proxy({}, { get(_target, property) {
                    const value = Reflect.get(input, property, input);
                    if (property === 'type')
                        convertedType = value === undefined ? undefined : `${value}`;
                    // Only local descriptions created for this peer may reverse.
                    // Remote signaling and candidates are never guessed from a
                    // realm-global masked string owned by another connection.
                    return name === 'setLocalDescription' && property === key && typeof value === 'string' ?
                        translations.reverse(receiver, input, convertedType, value) : property === 'type' ? convertedType : value;
                } }) : input;
            const result = Reflect.apply(native, receiver, args.length ? [translated, ...iterate(slice(args, 1))] : args);
            if (convertedType === 'rollback')
                return promiseThen(result, value => { translations.reset(receiver); return value; });
            return result;
        });
    }
    for (const name of iterate(['restartIce', 'close']))
        replaceMethod(proto, name, (native, peer, args) => {
            const result = Reflect.apply(native, peer, args);
            translations.reset(peer, name === 'close');
            return result;
        });
    markModule('webrtc', { status: 'partial', detail: 'candidate/statistics address observations; peer/type/generation-owned bounded local reversal; explicit relay-only transport and optional usable relay endpoints; real TURN acceptance, other ICE APIs, stats IDs/ports/performance and clean-realm recovery remain incomplete' });
}
