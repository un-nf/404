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

export function loadConfig() {
  const runtime = getRuntime()
  const raw = parseRawConfig()
  const fingerprint = raw && typeof raw.fingerprint === 'object' ? raw.fingerprint : raw
  const missing = REQUIRED_FIELDS.filter((key) => !fingerprint?.[key])

  if (!BROWSER_VARIANT_FIELDS.some((key) => fingerprint?.[key])) {
    missing.push('browser_variant')
  }

  if (missing.length > 0) {
    console.warn('[STATIC] profile missing required fields:', missing)
  }

  validateCoherence(fingerprint || {})

  runtime.config = {
    raw,
    fingerprint: fingerprint || {},
    ready: true,
  }

  Object.defineProperty(window, '__STATIC_CONFIG__', {
    get: () => runtime.config.raw,
    configurable: true,
    enumerable: false,
  })
  Object.defineProperty(window, '__STATIC_FINGERPRINT__', {
    get: () => runtime.config.fingerprint,
    configurable: true,
    enumerable: false,
  })
  Object.defineProperty(window, '__fpConfig', {
    get: () => runtime.config.fingerprint,
    configurable: true,
    enumerable: false,
  })
}

function parseRawConfig() {
  const currentScript = document.currentScript
  const encoded = currentScript?.getAttribute('data-static-config-b64')

  if (encoded) {
    try {
      return JSON.parse(window.atob(encoded))
    } catch (error) {
      console.error('[STATIC] failed to parse encoded profile JSON:', error)
    }
  }

  const node = document.getElementById('__static_profile')
  if (!node) {
    console.error('[STATIC] profile script tag missing')
    return {}
  }

  try {
    return JSON.parse(node.textContent || '{}')
  } catch (error) {
    console.error('[STATIC] failed to parse profile JSON:', error)
    return {}
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