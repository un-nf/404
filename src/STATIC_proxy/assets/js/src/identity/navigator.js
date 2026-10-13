import { getFingerprint } from '../core/config.js'
import { isFirefoxLike } from '../core/browser.js'
import { markModule } from '../core/guard.js'
import { replaceGetter, mapMethod } from '../core/descriptors.js'

export function installNavigator() {
  const fp = getFingerprint()
  const proto = Object.getPrototypeOf(globalThis.navigator)
  const languages = Object.freeze(Array.isArray(fp.languages) ? fp.languages.slice() :
    String(fp.languages || fp.language || 'en-US').split(',').map((x) => x.trim()).filter(Boolean))
  const values = {
    userAgent: fp.user_agent, platform: fp.platform, vendor: fp.vendor,
    vendorSub: fp.vendorSub, productSub: fp.productSub,
    appVersion: fp.app_version ?? fp.user_agent.replace(/^Mozilla\//, ''),
    hardwareConcurrency: fp.hardware_concurrency, maxTouchPoints: fp.max_touch_points,
    language: languages[0], languages, doNotTrack: fp.do_not_track,
    cookieEnabled: fp.cookie_enabled,
    oscpu: fp.oscpu, buildID: fp.buildID,
  }
  if (fp.device_memory !== undefined) values.deviceMemory = fp.device_memory
  const changed = [], unavailable = []
  for (const [name, value] of Object.entries(values)) {
    if (value !== undefined) (replaceGetter(proto, name, () => value) ? changed : unavailable).push(name)
  }
  const ua = globalThis.navigator.userAgentData
  if (ua && !isFirefoxLike(fp)) {
    const data = fp.ua_data || {}
    const brandValues = data.brands
    const brandArrays = new WeakMap()
    const copyBrand = (x) => ({ brand: x.brand, version: x.version })
    const mobile = data.mobile
    const platform = data.platform
    const hints = {
      brands: brandValues, mobile, platform, architecture: data.architecture,
      bitness: data.bitness, fullVersionList: data.full_version_list,
      model: data.model, platformVersion: data.platform_version,
      uaFullVersion: data.ua_full_version, wow64: data.wow64, formFactors: data.form_factors,
    }
    const uaProto = Object.getPrototypeOf(ua)
    replaceGetter(uaProto, 'brands', (nativeArray) => {
      if (!brandArrays.has(nativeArray)) brandArrays.set(nativeArray, Object.freeze(brandValues.map(copyBrand)))
      return brandArrays.get(nativeArray)
    })
    replaceGetter(uaProto, 'mobile', () => mobile)
    replaceGetter(uaProto, 'platform', () => platform)
    const mapResult = (result) => {
      const normalized = {}
      for (const key of Object.keys(result)) {
        if (hints[key] !== undefined) {
          normalized[key] = key === 'formFactors' ? hints[key].slice() :
            Array.isArray(hints[key]) ? hints[key].map(copyBrand) : hints[key]
        }
      }
      return normalized
    }
    mapMethod(uaProto, 'getHighEntropyValues', (promise) => promise.then(mapResult))
    mapMethod(uaProto, 'toJSON', mapResult)
  }
  markModule('navigator', { status: unavailable.length ? 'partial' : 'installed',
    changed: Object.freeze(changed), unavailable: Object.freeze(unavailable),
    uaData: !ua ? 'unavailable' : isFirefoxLike(fp) ? 'native' : 'installed',
    detail: 'existing host identity surfaces only; native UA data getter retained' })
}
