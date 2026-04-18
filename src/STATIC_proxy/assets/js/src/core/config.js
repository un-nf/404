import { getRuntime } from './guard.js'

const REQUIRED_FIELDS = [
  'user_agent',
  'platform',
  'browser_type',
  'canvas_hash',
  'webgl_vendor',
  'webgl_renderer',
]

export function loadConfig() {
  const runtime = getRuntime()
  const raw = parseRawConfig()
  const fingerprint = raw && typeof raw.fingerprint === 'object' ? raw.fingerprint : raw
  const missing = REQUIRED_FIELDS.filter((key) => !fingerprint?.[key])

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
  const browserType = fingerprint.browser_type || ''

  if (ua.includes('Windows') && !/Win/i.test(platform)) {
    console.warn('[STATIC] profile incoherence: UA is Windows but platform is', platform)
  }
  if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
    console.warn('[STATIC] profile incoherence: UA is macOS but platform is', platform)
  }
  if (browserType === 'chrome' && !vendor.includes('Google')) {
    console.warn('[STATIC] profile incoherence: browser_type is chrome but vendor is', vendor)
  }
  if (browserType === 'firefox' && ua.includes('Firefox') && fingerprint.sec_ch_ua) {
    console.warn('[STATIC] profile incoherence: Firefox profile contains sec_ch_ua client hints')
  }
}

export function getConfig() {
  return getRuntime().config
}

export function getFingerprint() {
  return getRuntime().config?.fingerprint || {}
}