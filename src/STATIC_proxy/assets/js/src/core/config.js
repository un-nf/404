import { getRuntime } from './guard.js'
import { isChromiumLike, isFirefoxLike, resolveBrowserFamily, resolveBrowserVariant } from './browser.js'

const REQUIRED_FIELDS = [
  'user_agent',
  'platform',
  'canvas_hash',
  'webgl_vendor',
  'webgl_renderer',
]

const BROWSER_VARIANT_FIELDS = ['browser_variant', 'profile_variant', 'browser_type']

export function loadConfig(input) {
  const runtime = getRuntime()
  // Clone inputs before freezing so another realm never shares mutable persona state.
  const raw = JSON.parse(JSON.stringify(input === undefined ? parseRawConfig() : input))
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('STATIC profile must be an object')
  }
  const fingerprint = raw && typeof raw.fingerprint === 'object' ? raw.fingerprint : raw
  if (!fingerprint || Array.isArray(fingerprint)) {
    throw new TypeError('STATIC fingerprint must be an object')
  }
  const missing = REQUIRED_FIELDS.filter((key) => !fingerprint?.[key])

  if (!BROWSER_VARIANT_FIELDS.some((key) => fingerprint?.[key])) {
    missing.push('browser_variant')
  }

  if (missing.length > 0) {
    throw new TypeError(`STATIC profile missing required fields: ${missing.join(', ')}`)
  }

  for (const field of REQUIRED_FIELDS) {
    if (typeof fingerprint[field] !== 'string' || !fingerprint[field].trim()) {
      throw new TypeError(`STATIC profile field ${field} must be a nonempty string`)
    }
  }
  const variantValues = BROWSER_VARIANT_FIELDS.filter((key) => fingerprint[key] !== undefined)
    .map((key) => String(fingerprint[key]).trim().toLowerCase())
  const firefoxVariants = ['firefox', 'gecko', 'tor', 'mullvad']
  const chromiumVariants = ['chrome', 'chromium', 'edge', 'brave', 'vivaldi', 'opera']
  if (variantValues.some((value) => ![...firefoxVariants, ...chromiumVariants].includes(value)) ||
      new Set(variantValues).size !== 1) {
    throw new TypeError('STATIC browser variant is unsupported or conflicting')
  }
  const expectedFamily = firefoxVariants.includes(variantValues[0]) ? 'firefox-like' : 'chromium-like'
  for (const key of ['browser_family', 'profile_family']) {
    if (fingerprint[key] !== undefined && fingerprint[key] !== expectedFamily) {
      throw new TypeError('STATIC browser family conflicts with variant')
    }
  }
  for (const [key, value] of Object.entries(fingerprint)) {
    if (key.startsWith('enable_') && typeof value !== 'boolean') {
      throw new TypeError(`STATIC profile flag ${key} must be boolean`)
    }
  }
  for (const key of ['default_stride', 'small_canvas_stride']) {
    const value = fingerprint.canvas_noise?.[key]
    if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) {
      throw new TypeError(`STATIC canvas_noise.${key} must be a positive integer`)
    }
  }

  for (const key of ['vendor', 'vendorSub', 'productSub', 'oscpu', 'buildID', 'language', 'effective_type', 'connection_type']) {
    if (fingerprint[key] !== undefined && typeof fingerprint[key] !== 'string') {
      throw new TypeError(`STATIC ${key} must be a string`)
    }
  }
  if (fingerprint.do_not_track !== undefined && fingerprint.do_not_track !== null && typeof fingerprint.do_not_track !== 'string') {
    throw new TypeError('STATIC do_not_track must be a string or null')
  }
  if (fingerprint.languages !== undefined && !(typeof fingerprint.languages === 'string' ||
      Array.isArray(fingerprint.languages) && fingerprint.languages.every((value) => typeof value === 'string' && value.length))) {
    throw new TypeError('STATIC languages must contain strings')
  }
  for (const key of ['hardware_concurrency', 'max_touch_points']) {
    const value = fingerprint[key]
    if (value !== undefined && (!Number.isSafeInteger(value) || value > 0xffffffff || value < (key === 'hardware_concurrency' ? 1 : 0))) {
      throw new TypeError(`STATIC ${key} has an invalid integer range`)
    }
  }
  if (fingerprint.rtt !== undefined && (!Number.isInteger(fingerprint.rtt) || fingerprint.rtt > 0xffffffff)) {
    throw new TypeError('STATIC rtt must fit an unsigned long')
  }
  for (const key of ['device_memory', 'device_pixel_ratio', 'downlink', 'rtt']) {
    const value = fingerprint[key]
    if (value !== undefined && (!Number.isFinite(value) || value < 0 ||
        ['device_memory', 'device_pixel_ratio'].includes(key) && value === 0)) {
      throw new TypeError(`STATIC ${key} has an invalid numeric range`)
    }
  }
  const uaData = fingerprint.ua_data
  if (uaData !== undefined) {
    if (!uaData || typeof uaData !== 'object' || Array.isArray(uaData)) throw new TypeError('STATIC ua_data must be an object')
    for (const key of ['brands', 'full_version_list']) {
      if (uaData[key] !== undefined && !(Array.isArray(uaData[key]) && uaData[key].every((entry) =>
          entry && typeof entry.brand === 'string' && typeof entry.version === 'string'))) {
        throw new TypeError(`STATIC ua_data.${key} must contain brand/version strings`)
      }
    }
    if (uaData.mobile !== undefined && typeof uaData.mobile !== 'boolean') throw new TypeError('STATIC ua_data.mobile must be boolean')
    for (const key of ['platform', 'platform_version', 'architecture', 'bitness', 'model', 'ua_full_version']) {
      if (uaData[key] !== undefined && typeof uaData[key] !== 'string') throw new TypeError(`STATIC ua_data.${key} must be a string`)
    }
  }
  if (fingerprint.media_devices !== undefined && !(Array.isArray(fingerprint.media_devices) &&
      fingerprint.media_devices.every((entry) => entry && ['audioinput', 'audiooutput', 'videoinput'].includes(entry.kind) &&
        (entry.label === undefined || typeof entry.label === 'string')))) {
    throw new TypeError('STATIC media_devices must contain valid kinds and string labels')
  }

  if (fingerprint.timezone !== undefined) {
    if (typeof fingerprint.timezone !== 'string') throw new TypeError('STATIC timezone must be a string')
    new Intl.DateTimeFormat('en-US', { timeZone: fingerprint.timezone })
  }
  for (const key of ['storage_quota', 'storage_usage', 'storage_usage_quantum', 'speech_voice_limit', 'media_devices_per_kind', 'media_device_count']) {
    const value = fingerprint[key]
    if (value !== undefined && (!Number.isSafeInteger(value) || value < (key === 'storage_usage' ? 0 : 1))) {
      throw new TypeError(`STATIC ${key} must be a safe integer in range`)
    }
  }
  for (const key of ['cookie_enabled', 'save_data']) {
    if (fingerprint[key] !== undefined && typeof fingerprint[key] !== 'boolean') {
      throw new TypeError(`STATIC ${key} must be boolean`)
    }
  }
  if (fingerprint.storage_usage !== undefined && fingerprint.storage_usage > (fingerprint.storage_quota ?? 107374182400)) {
    throw new TypeError('STATIC storage_usage exceeds persona quota')
  }
  if (fingerprint.speech_languages !== undefined && !(Array.isArray(fingerprint.speech_languages) &&
      fingerprint.speech_languages.length && fingerprint.speech_languages.every((value) => typeof value === 'string' && value))) {
    throw new TypeError('STATIC speech_languages must contain language strings')
  }
  if (fingerprint.speech_voices !== undefined && !(Array.isArray(fingerprint.speech_voices) &&
      fingerprint.speech_voices.every((voice) => voice && typeof voice.lang === 'string' && voice.lang &&
        ['name', 'voiceURI'].every((key) => voice[key] === undefined || typeof voice[key] === 'string')))) {
    throw new TypeError('STATIC speech_voices must contain language and optional metadata strings')
  }
  if (fingerprint.permission_states !== undefined && (!fingerprint.permission_states ||
      typeof fingerprint.permission_states !== 'object' || Array.isArray(fingerprint.permission_states) ||
      Object.values(fingerprint.permission_states).some((value) => !['denied', 'prompt', 'native'].includes(value)) ||
      fingerprint.permission_states.notifications !== undefined &&
        !['denied', 'native'].includes(fingerprint.permission_states.notifications))) {
    throw new TypeError('STATIC permission_states must specify denied, prompt or native; notifications denied or native')
  }
  if (fingerprint.media_capabilities !== undefined && (!fingerprint.media_capabilities ||
      typeof fingerprint.media_capabilities !== 'object' || Array.isArray(fingerprint.media_capabilities) ||
      Object.entries(fingerprint.media_capabilities).some(([key, value]) =>
        !['smooth', 'power_efficient'].includes(key) || typeof value !== 'boolean'))) {
    throw new TypeError('STATIC media_capabilities must specify boolean smooth/power_efficient')
  }
  validateCoherence(fingerprint || {})

  runtime.config = deepFreeze({
    raw,
    fingerprint: fingerprint || {},
    ready: true,
  })
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

function parseRawConfig() {
  const currentScript = document.currentScript
  const encoded = currentScript?.getAttribute('data-static-config-b64')

  if (encoded) {
    currentScript.removeAttribute('data-static-config-b64')
    try {
      const bytes = Uint8Array.from(window.atob(encoded), (char) => char.charCodeAt(0))
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch (error) {
      throw new TypeError('STATIC encoded profile is invalid', { cause: error })
    }
  }

  const node = document.getElementById('__static_profile')
  if (!node) {
    console.error('[STATIC] profile script tag missing')
    return {}
  }

  try {
    const text = node.textContent
    node.remove()
    return JSON.parse(text || '{}')
  } catch (error) {
    throw new TypeError('STATIC profile JSON is invalid', { cause: error })
  }
}

function validateCoherence(fingerprint) {
  const ua = fingerprint.user_agent || ''
  const platform = fingerprint.platform || ''
  const vendor = fingerprint.vendor || ''
  const family = resolveBrowserFamily(fingerprint)
  const variant = resolveBrowserVariant(fingerprint)

  if (ua.includes('Windows') && !/Win/i.test(platform)) {
    console.warn('[STATIC] profile incoherence: UA is Windows but platform is', platform)
  }
  if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
    console.warn('[STATIC] profile incoherence: UA is macOS but platform is', platform)
  }
  if (variant === 'chrome' && !vendor.includes('Google')) {
    console.warn('[STATIC] profile incoherence: chrome variant is missing a Google vendor string', vendor)
  }
  if (variant === 'edge' && ua.includes('Edg/') === false) {
    console.warn('[STATIC] profile incoherence: edge variant is missing Edg/ token in UA')
  }
  if (isFirefoxLike(fingerprint) && ua.includes('Firefox') && fingerprint.sec_ch_ua) {
    console.warn('[STATIC] profile incoherence: Firefox profile contains sec_ch_ua client hints')
  }
  if (fingerprint.browser_family && fingerprint.browser_family !== family) {
    console.warn('[STATIC] profile incoherence: browser_family does not match resolved family', fingerprint.browser_family, family)
  }
  if (fingerprint.browser_variant && fingerprint.browser_variant !== variant) {
    console.warn('[STATIC] profile incoherence: browser_variant does not match resolved variant', fingerprint.browser_variant, variant)
  }
  if (isChromiumLike(fingerprint) && !ua.includes('AppleWebKit/537.36')) {
    console.warn('[STATIC] profile incoherence: chromium-like profile is missing AppleWebKit token')
  }
}

export function getConfig() {
  return getRuntime().config
}

export function getFingerprint() {
  return getRuntime().config?.fingerprint || {}
}
