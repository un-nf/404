import schema from '../../../../schema/runtime-profile.schema.json'

export function validateValue(value, rule, path = 'fingerprint') {
  const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
  const expected = Array.isArray(rule.type) ? rule.type : [rule.type]
  if (rule.type && !expected.some((kind) => kind === type || kind === 'integer' && Number.isSafeInteger(value))) {
    throw new TypeError(`STATIC ${path}: invalid type`)
  }
  if (typeof value === 'number' && (!Number.isFinite(value) || value < (rule.minimum ?? -Infinity) || value > (rule.maximum ?? Infinity))) {
    throw new TypeError(`STATIC ${path}: invalid range`)
  }
  if (typeof value === 'string' && value.length < (rule.minLength ?? 0)) throw new TypeError(`STATIC ${path}: empty string`)
  if (rule.enum && !rule.enum.includes(value)) throw new TypeError(`STATIC ${path}: invalid enum`)
  if (Array.isArray(value) && rule.items) value.forEach((item, index) => validateValue(item, rule.items, `${path}[${index}]`))
  else if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of rule.required || []) if (!(key in value)) throw new TypeError(`STATIC ${path}.${key}: required`)
    for (const [key, item] of Object.entries(value)) {
      const child = rule.properties?.[key] ?? rule.additionalProperties
      if (child === false) throw new TypeError(`STATIC ${path}.${key}: unknown field`)
      if (child && typeof child === 'object') validateValue(item, child, `${path}.${key}`)
    }
  }
}

export function normalizeFingerprint(value) {
  validateValue(value, schema)
  for (const [key, rule] of Object.entries(schema.properties)) {
    if (rule['x-alias'] && value[key] !== undefined) {
      const canonical = rule['x-alias']
      if (value[canonical] !== undefined && value[canonical] !== value[key]) throw new TypeError(`STATIC conflicting ${key}/${canonical}`)
      value[canonical] = value[key]
    }
  }
  for (const [key, rule] of Object.entries(schema.properties)) {
    if (value[key] === undefined && rule.default !== undefined) value[key] = rule.default
  }
  const unsupported = Object.entries(value).filter(([key]) => schema.properties[key]?.['x-runtime'] === 'unsupported-or-metadata')
    .map(([key]) => key)
  return Object.freeze({ unsupported: Object.freeze(unsupported) })
}
