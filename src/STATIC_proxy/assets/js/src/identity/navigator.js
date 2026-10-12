import { getFingerprint } from '../core/config.js'
import { defaultUaDataBrands, isFirefoxLike } from '../core/browser.js'
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
    appVersion: fp.user_agent.replace(/^Mozilla\//, ''),
    hardwareConcurrency: fp.hardware_concurrency, maxTouchPoints: fp.max_touch_points,
    language: languages[0], languages, doNotTrack: fp.do_not_track,
    cookieEnabled: fp.cookie_enabled,
    oscpu: fp.oscpu, buildID: fp.buildID,
  }
  if (fp.device_memory !== undefined) {
    const allowed = [0.25, 0.5, 1, 2, 4, 8]
    values.deviceMemory = allowed.reduce((best, x) =>
      Math.abs(x - fp.device_memory) < Math.abs(best - fp.device_memory) ? x : best, 8)
  }
  const changed = [], unavailable = []
  for (const [name, value] of Object.entries(values)) {
    if (value !== undefined) (replaceGetter(proto, name, () => value) ? changed : unavailable).push(name)
  }
  const ua = globalThis.navigator.userAgentData
  if (ua && !isFirefoxLike(fp)) {
    const data = fp.ua_data || {}
    const brandValues = data.brands || defaultUaDataBrands(fp)
    const brandArrays = new WeakMap()
    const copyBrand = (x) => ({ brand: x.brand, version: x.version })
    const mobile = data.mobile ?? false
    const platform = data.platform || String(fp.sec_ch_ua_platform || fp.platform).replace(/^"|"$/g, '')
    const hints = {
      brands: brandValues, mobile, platform, architecture: data.architecture,
      bitness: data.bitness, fullVersionList: data.full_version_list,
      model: data.model, platformVersion: data.platform_version,
      uaFullVersion: data.ua_full_version || fp.browser_version,
    }
    const uaProto = Object.getPrototypeOf(ua)
    replaceGetter(uaProto, 'brands', (nativeArray) => {
      if (!brandArrays.has(nativeArray)) brandArrays.set(nativeArray, Object.freeze(brandValues.map(copyBrand)))
      return brandArrays.get(nativeArray)
    })
    replaceGetter(uaProto, 'mobile', () => mobile)
    replaceGetter(uaProto, 'platform', () => platform)
    const mapResult = (result) => {
      for (const key of Object.keys(result)) {
        if (hints[key] !== undefined) {
          result[key] = Array.isArray(hints[key]) ? hints[key].map(copyBrand) : hints[key]
        }
      }
      return result
    }
    mapMethod(uaProto, 'getHighEntropyValues', (promise) => promise.then(mapResult))
    mapMethod(uaProto, 'toJSON', mapResult)
  }
  markModule('navigator', { status: unavailable.length ? 'partial' : 'installed',
    changed: Object.freeze(changed), unavailable: Object.freeze(unavailable),
    uaData: !ua ? 'unavailable' : isFirefoxLike(fp) ? 'native' : 'installed',
    detail: 'existing host identity surfaces only; native UA data getter retained' })
}
