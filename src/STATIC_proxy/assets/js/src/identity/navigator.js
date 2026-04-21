import { getFingerprint } from '../core/config.js'
import { defaultUaDataBrands, isFirefoxLike } from '../core/browser.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function defineNavigatorGetter(name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, name)
  const namedGetter = { [name]: function getter() { return fn() } }[name]
  markNativeCode(namedGetter, name)
  Object.defineProperty(Navigator.prototype, name, {
    get: namedGetter,
    configurable: descriptor?.configurable ?? true,
    enumerable: descriptor?.enumerable ?? true,
  })
}


function normalizeLanguages(languages) {
  if (Array.isArray(languages)) {
    return languages.slice()
  }
  return String(languages || 'en-US').split(',').map((value) => value.trim()).filter(Boolean)
}

function normalizeDeviceMemory(value) {
  if (value == null) {
    return undefined
  }
  const candidates = [0.25, 0.5, 1, 2, 4, 8]
  const numeric = Number(value)
  return candidates.reduce((best, current) => {
    if (!Number.isFinite(numeric)) {
      return 8
    }
    return Math.abs(current - numeric) < Math.abs(best - numeric) ? current : best
  }, 8)
}

function deriveOscpu(platform) {
  if (!platform) {
    return undefined
  }
  if (platform.includes('Win')) {
    return 'Windows NT 10.0; Win64; x64'
  }
  if (platform.includes('Mac')) {
    return 'Intel Mac OS X 10.15'
  }
  if (platform.includes('Linux')) {
    return 'Linux x86_64'
  }
  return undefined
}

function buildUserAgentData(fingerprint) {
  const uaData = fingerprint.ua_data || {}
  const brands = uaData.brands || defaultUaDataBrands(fingerprint)
  const mobile = uaData.mobile || false
  const platform = uaData.platform || fingerprint.sec_ch_ua_platform || fingerprint.platform || ''

  const object = {
    brands,
    mobile,
    platform,
    getHighEntropyValues: markNativeCode(async function getHighEntropyValues(hints) {
      const values = {
        architecture: uaData.architecture || 'x86',
        bitness: uaData.bitness || '64',
        brands,
        fullVersionList: uaData.full_version_list || brands,
        mobile,
        model: uaData.model || '',
        platform,
        platformVersion: uaData.platform_version || '10.0.0',
        uaFullVersion: uaData.ua_full_version || fingerprint.browser_version || '',
      }
      const result = {}
      for (const hint of hints || []) {
        if (Object.prototype.hasOwnProperty.call(values, hint)) {
          result[hint] = values[hint]
        }
      }
      return result
    }, 'getHighEntropyValues'),
    toJSON: markNativeCode(function toJSON() {
      return { brands, mobile, platform }
    }, 'toJSON'),
  }

  return Object.freeze(object)
}

export function installNavigator() {
  const fingerprint = getFingerprint()
  const isFirefox = isFirefoxLike(fingerprint)
  const languages = normalizeLanguages(fingerprint.languages || fingerprint.language || 'en-US')

  defineNavigatorGetter('userAgent', () => fingerprint.user_agent || navigator.userAgent)
  defineNavigatorGetter('platform', () => fingerprint.platform || navigator.platform)
  defineNavigatorGetter('vendor', () => fingerprint.vendor ?? (isFirefox ? '' : 'Google Inc.'))
  defineNavigatorGetter('vendorSub', () => fingerprint.vendorSub ?? '')
  defineNavigatorGetter('product', () => 'Gecko')
  defineNavigatorGetter('productSub', () => fingerprint.productSub ?? (isFirefox ? '20100101' : '20030107'))
  defineNavigatorGetter('appCodeName', () => 'Mozilla')
  defineNavigatorGetter('appName', () => 'Netscape')
  defineNavigatorGetter('appVersion', () => {
    if (fingerprint.user_agent) {
      return fingerprint.user_agent.replace(/^Mozilla\//, '')
    }
    return navigator.appVersion
  })
  defineNavigatorGetter('hardwareConcurrency', () => fingerprint.hardware_concurrency ?? 8)
  defineNavigatorGetter('deviceMemory', () => {
    if (fingerprint.device_memory == null && isFirefox) {
      return undefined
    }
    return normalizeDeviceMemory(fingerprint.device_memory ?? 8)
  })
  defineNavigatorGetter('maxTouchPoints', () => fingerprint.max_touch_points ?? 0)
  defineNavigatorGetter('language', () => languages[0] || 'en-US')
  defineNavigatorGetter('languages', () => Object.freeze(languages.slice()))
  defineNavigatorGetter('doNotTrack', () => fingerprint.do_not_track ?? null)
  defineNavigatorGetter('cookieEnabled', () => fingerprint.cookie_enabled !== false)
  defineNavigatorGetter('pdfViewerEnabled', () => fingerprint.pdf_viewer_enabled ?? !isFirefox)

  if (isFirefox) {
    defineNavigatorGetter('oscpu', () => fingerprint.oscpu || deriveOscpu(fingerprint.platform))
    defineNavigatorGetter('buildID', () => fingerprint.buildID || '20251106203603')
  } else {
    defineNavigatorGetter('vendorFlavors', () => Object.freeze(fingerprint.vendor_flavors || []))
    defineNavigatorGetter('userAgentData', () => buildUserAgentData(fingerprint))
  }

  markModule('navigator')
}