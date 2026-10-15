import { regexpTest, iterate, iterateEntries } from './primordials.js';
import { arraySome, stringTrim, stringSplit, includes, stringLower, arrayForEach, arrayMap, arrayFilter, ObjectIntrinsic as Object, ArrayIntrinsic as Array, JSONIntrinsic as JSON, NumberIntrinsic as Number } from './primordials.js';
import schema from '../../../../schema/runtime-profile.schema.json';
import { validateSemantics } from './semantics.js';
export const variantFamilies = Object.freeze(schema['x-variant-families']);
export function validateValue(value, rule, path = 'fingerprint') {
    if (rule.anyOf && !arraySome(rule.anyOf, (branch) => {
        try {
            validateValue(value, branch, path);
            return true;
        }
        catch {
            return false;
        }
    })) {
        throw new TypeError(`STATIC ${path}: no supported variant`);
    }
    const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    const expected = Array.isArray(rule.type) ? rule.type : [rule.type];
    if (rule.type && !arraySome(expected, (kind) => kind === type || kind === 'integer' && Number.isSafeInteger(value))) {
        throw new TypeError(`STATIC ${path}: invalid type`);
    }
    if (typeof value === 'number' && (!Number.isFinite(value) || value < (rule.minimum ?? -Infinity) || value > (rule.maximum ?? Infinity))) {
        throw new TypeError(`STATIC ${path}: invalid range`);
    }
    if (typeof value === 'string' && value.length < (rule.minLength ?? 0))
        throw new TypeError(`STATIC ${path}: empty string`);
    if (typeof value === 'string' && rule['x-nonempty'] && !stringTrim(value))
        throw new TypeError(`STATIC ${path}: empty string`);
    if (rule['x-http-string'] && !regexpTest(/^[\x20-\x7e]*$/, value))
        throw new TypeError(`STATIC ${path}: invalid HTTP string`);
    if (rule['x-resolution'] && (!regexpTest(/^[0-9]+x[0-9]+$/, value) || arraySome(stringSplit(value, 'x'), part => !Number.isSafeInteger(Number(part)) || Number(part) < 1 || Number(part) > 131072)))
        throw new TypeError(`STATIC ${path}: invalid resolution`);
    if (rule.enum && !includes(rule.enum, rule['x-casefold'] && typeof value === 'string' ? stringLower(stringTrim(value)) : value))
        throw new TypeError(`STATIC ${path}: invalid enum`);
    if (Array.isArray(value) && (value.length < (rule.minItems ?? 0) || value.length > (rule.maxItems ?? Infinity)))
        throw new TypeError(`STATIC ${path}: invalid array length`);
    if (Array.isArray(value) && rule.items)
        arrayForEach(value, (item, index) => validateValue(item, rule.items, `${path}[${index}]`));
    else if (value && typeof value === 'object' && !Array.isArray(value)) {
        for (const key of iterate(rule.required || []))
            if (!(key in value))
                throw new TypeError(`STATIC ${path}.${key}: required`);
        for (const [key, item] of iterateEntries(Object.entries(value))) {
            const child = rule.properties?.[key] ?? rule.additionalProperties;
            if (child === false)
                throw new TypeError(`STATIC ${path}.${key}: unknown field`);
            if (child && typeof child === 'object')
                validateValue(item, child, `${path}.${key}`);
        }
    }
}
export function normalizeFingerprint(value) {
    const data = value.ua_data;
    if (data?.formFactors !== undefined) {
        if (data.form_factors !== undefined && JSON.stringify(data.form_factors) !== JSON.stringify(data.formFactors))
            throw new TypeError('STATIC conflicting formFactors/form_factors');
        data.form_factors = data.formFactors;
    }
    validateValue(value, schema);
    validateSemantics(value);
    for (const [key, rule] of iterateEntries(Object.entries(schema.properties))) {
        if (rule['x-alias'] && value[key] !== undefined) {
            const canonical = rule['x-alias'];
            if (value[canonical] !== undefined && value[canonical] !== value[key])
                throw new TypeError(`STATIC conflicting ${key}/${canonical}`);
            value[canonical] = value[key];
        }
    }
    for (const [key, rule] of iterateEntries(Object.entries(schema.properties))) {
        if (value[key] === undefined && rule.default !== undefined)
            value[key] = rule.default;
    }
    const unsupported = arrayMap(arrayFilter(Object.entries(value), ([key]) => schema.properties[key]?.['x-runtime'] === 'unsupported-or-metadata'), ([key]) => key);
    const partial = arrayMap(arrayFilter(Object.entries(value), ([key]) => schema.properties[key]?.['x-runtime'] === 'partial'), ([key]) => key);
    return Object.freeze({ unsupported: Object.freeze(unsupported), partial: Object.freeze(partial) });
}
