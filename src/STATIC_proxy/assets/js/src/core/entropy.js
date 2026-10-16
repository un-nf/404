import { stringCharCodeAt, arrayJoin, stringPadStart, numberString, ObjectIntrinsic as Object, ArrayIntrinsic as Array, MathIntrinsic as Math, StringIntrinsic as String, Uint32ArrayIntrinsic as Uint32Array } from './primordials.js';
import { getRuntime } from './guard.js';
import { randomValues, dateNow } from './primordials.js';
function xorshift32(seed) {
    let state = (seed >>> 0) || 1;
    return function next() {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        return (state >>> 0) / 0x100000000;
    };
}
function hashString(input) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < input.length; index += 1) {
        hash ^= stringCharCodeAt(input, index);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash;
}
function secureRandomUint32() {
    if (randomValues) {
        return randomValues(new Uint32Array(1))[0];
    }
    throw new TypeError('STATIC requires a cryptographic entropy source');
}
export function initEntropy() {
    const runtime = getRuntime();
    const fingerprint = runtime.config?.fingerprint || {};
    const startupSalt = String(runtime.config?.raw?.startup_salt || '');
    const driftEnabled = fingerprint.enable_fingerprint_drift !== false;
    const sessionId = driftEnabled
        // Public bootstrap salts are correlation tokens, not private noise keys.
        ? privateSessionId()
        : 'static';
    const origin = (() => {
        try {
            return typeof globalThis.origin === 'string' ? globalThis.origin : location.origin;
        }
        catch {
            return 'opaque';
        }
    })();
    const realm = typeof WorkerGlobalScope === 'function' && globalThis instanceof WorkerGlobalScope ? 'worker' : 'window';
    const sessionSeed = hashString(`${sessionId}:${origin}:${realm}:${fingerprint.canvas_hash || ''}`);
    const originSeed = hashString(`${sessionId}:${origin}`);
    runtime.entropy = Object.freeze({
        sessionId,
        origin,
        realm,
        startupSalt,
        sessionSeed,
        originSeed,
        sessionRng: xorshift32(sessionSeed),
        originRng: xorshift32(originSeed),
        hash: hashString,
        rng: xorshift32,
    });
}
function privateSessionId() {
    if(!randomValues)throw new TypeError('STATIC requires a cryptographic entropy source');
    const words=randomValues(new Uint32Array(4));let output='';
    for(let index=0;index<4;index++)output+=stringPadStart(numberString(words[index],16),8,'0');
    return output;
}
