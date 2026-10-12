import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { findDescriptor, replaceMethod } from '../core/descriptors.js'

export function installWebGLSpoof() {
  const fp = getFingerprint()
  const prototypes = [globalThis.WebGLRenderingContext?.prototype, globalThis.WebGL2RenderingContext?.prototype]
  let installed = 0
  for (const proto of prototypes) {
    if (!proto) continue
    const validate = findDescriptor(proto, 'getContextAttributes')?.descriptor.value
    if (!validate) continue
    const overrides = new Map()
    for (const [name, value] of Object.entries(fp.webgl_parameters || {})) {
      const constant = findDescriptor(proto, name)?.descriptor.value
      const key = typeof constant === 'number' ? constant : Number(name)
      if (Number.isFinite(key)) overrides.set(key, value)
    }
    installed += Number(replaceMethod(proto, 'getParameter', (native, receiver, args) => {
      if (!args.length) return Reflect.apply(native, receiver, args)
      // Validate before coercion; coerce GLenum once, with native Symbol/BigInt
      // rejection. Keep the genuine context instead of proxying its brand.
      Reflect.apply(validate, receiver, [])
      const parameter = (+args[0]) >>> 0
      const value = Reflect.apply(native, receiver, [parameter, ...args.slice(1)])
      if (value === null) return value
      if (parameter === 0x9245) return fp.webgl_vendor
      if (parameter === 0x9246) return fp.webgl_renderer
      if (parameter === 0x1f00 && fp.webgl_standard_vendor) return fp.webgl_standard_vendor
      if (parameter === 0x1f01 && fp.webgl_standard_renderer) return fp.webgl_standard_renderer
      if (!overrides.has(parameter)) return value
      const configured = overrides.get(parameter)
      if (ArrayBuffer.isView(value) && Array.isArray(configured) && value.length === configured.length) {
        if ((parameter === 0x846d || parameter === 0x846e) && value.length === 2) {
          const lower = Number.isFinite(configured[0]) ? Math.max(value[0], Math.min(value[1], configured[0])) : value[0]
          const upper = Number.isFinite(configured[1]) ? Math.max(lower, Math.min(value[1], configured[1])) : value[1]
          return new value.constructor([lower, upper])
        }
        return new value.constructor(Array.from(value, (x, i) =>
          Number.isFinite(configured[i]) && configured[i] >= 0 ? Math.min(x, configured[i]) : x))
      }
      // Only lower advertised positive capacity limits, never invent support.
      if (Number.isInteger(value) && value >= 0 && Number.isInteger(configured) && configured >= 0) {
        return Math.min(value, configured)
      }
      return value
    }))
  }
  markModule('webgl', { status: installed ? 'partial' : 'unavailable',
    detail: 'native contexts/extensions and WebGL versions; supported metadata/limits only; rendering remains native' })
}
