import { iterateEntries, iterate } from './primordials.js';
import { includes, ObjectIntrinsic as Object, JSONIntrinsic as JSON, MapIntrinsic as Map } from './primordials.js';
import parameters from '../../../../schema/webgl-parameters.json';
export function resolveWebGLParameter(name, kind) {
    const rule = Object.hasOwn(parameters, name) ? parameters[name] : null;
    if (!rule || !includes(rule.versions, kind))
        throw new TypeError(`STATIC unresolved ${kind} parameter ${name}`);
    return rule.enum;
}
export function resolveWebGLParameters(fingerprint) {
    const configured = new Map();
    for (const kind of iterate(['webgl1', 'webgl2'])) {
        const mapped = new Map();
        for (const [name, value] of iterateEntries(Object.entries(fingerprint.webgl_contexts?.[kind]?.parameters || {}))) {
            const key = resolveWebGLParameter(name, kind);
            if (mapped.has(key) && JSON.stringify(mapped.get(key)) !== JSON.stringify(value))
                throw new TypeError(`STATIC conflicting ${kind} parameter aliases for ${name}`);
            mapped.set(key, value);
        }
        configured.set(kind, mapped);
    }
    return configured;
}
