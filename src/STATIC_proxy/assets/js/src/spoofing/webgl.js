import { getFingerprint } from '../core/config.js'
import { isFirefoxLike } from '../core/browser.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const VENDOR_ENUM = 0x1f00
const RENDERER_ENUM = 0x1f01
const VERSION_ENUM = 0x1f02
const SHADING_LANGUAGE_VERSION_ENUM = 0x8b8c
const DEBUG_VENDOR_ENUM = 0x9245
const DEBUG_RENDERER_ENUM = 0x9246
const contextProxyMap = new WeakMap()

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function normalizeContextType(type) {
  return typeof type === 'string' ? type.toLowerCase() : ''
}

function isWebGLContextType(type) {
  const normalized = normalizeContextType(type)
  return normalized === 'webgl' || normalized === 'experimental-webgl' || normalized === 'webgl2'
}

function cloneValue(value) {
  if (Array.isArray(value)) {
    return value.slice()
  }
  if (ArrayBuffer.isView(value)) {
    return new value.constructor(value)
  }
  return value
}

function buildParameterMap(gl, fingerprint) {
  const overrides = new Map()
  const parameters = fingerprint.webgl_parameters || {}

  for (const [name, value] of Object.entries(parameters)) {
    const numericKey = typeof gl[name] === 'number' ? gl[name] : Number(name)
    if (Number.isFinite(numericKey)) {
      overrides.set(numericKey, value)
    }
  }

  return overrides
}

function resolveStandardStrings(fingerprint) {
  const isFirefox = isFirefoxLike(fingerprint)

  return {
    vendor: fingerprint.webgl_standard_vendor || (isFirefox ? 'Mozilla' : 'WebKit'),
    renderer: fingerprint.webgl_standard_renderer || (isFirefox ? 'Mozilla' : 'WebKit WebGL'),
    version: fingerprint.webgl_version || (isFirefox ? 'WebGL 1.0' : 'WebGL 1.0 (OpenGL ES 2.0 Chromium)'),
    shadingLanguageVersion: fingerprint.webgl_shading_language_version
      || (isFirefox ? 'WebGL GLSL ES 1.0' : 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)'),
  }
}

function createProxyForContext(context, fingerprint) {
  if (!context) {
    return context
  }
  if (contextProxyMap.has(context)) {
    return contextProxyMap.get(context)
  }

  const vendor = fingerprint.webgl_vendor || 'Intel Inc.'
  const renderer = fingerprint.webgl_renderer || 'Intel(R) UHD Graphics 770'
  const standardStrings = resolveStandardStrings(fingerprint)
  const overrides = buildParameterMap(context, fingerprint)

  const proxy = new Proxy(context, {
    get(target, prop, receiver) {
      if (prop === '__static_webgl_proxy') {
        return proxy
      }

      if (prop === 'getParameter') {
        return markNativeCode(function getParameter(parameter) {
          const resolved = typeof parameter === 'number' ? parameter : Number(parameter)
          if (resolved === VENDOR_ENUM || parameter === target.VENDOR) {
            return standardStrings.vendor
          }
          if (resolved === RENDERER_ENUM || parameter === target.RENDERER) {
            return standardStrings.renderer
          }
          if (resolved === VERSION_ENUM || parameter === target.VERSION) {
            return standardStrings.version
          }
          if (resolved === SHADING_LANGUAGE_VERSION_ENUM || parameter === target.SHADING_LANGUAGE_VERSION) {
            return standardStrings.shadingLanguageVersion
          }
          if (resolved === DEBUG_VENDOR_ENUM || parameter === target.UNMASKED_VENDOR_WEBGL) {
            return vendor
          }
          if (resolved === DEBUG_RENDERER_ENUM || parameter === target.UNMASKED_RENDERER_WEBGL) {
            return renderer
          }
          if (overrides.has(resolved)) {
            return cloneValue(overrides.get(resolved))
          }
          return target.getParameter.call(target, parameter)
        }, 'getParameter')
      }

      if (prop === 'getExtension') {
        return markNativeCode(function getExtension(name) {
          const extension = target.getExtension ? target.getExtension.call(target, name) : null
          if (!extension || String(name) !== 'WEBGL_debug_renderer_info') {
            return extension
          }
          return new Proxy(extension, {
            get(extensionTarget, extensionProp) {
              if (extensionProp === 'UNMASKED_VENDOR_WEBGL') {
                return DEBUG_VENDOR_ENUM
              }
              if (extensionProp === 'UNMASKED_RENDERER_WEBGL') {
                return DEBUG_RENDERER_ENUM
              }
              const value = Reflect.get(extensionTarget, extensionProp)
              return typeof value === 'function' ? value.bind(extensionTarget) : value
            },
          })
        }, 'getExtension')
      }

      if (prop === 'getSupportedExtensions') {
        return markNativeCode(function getSupportedExtensions() {
          const supported = target.getSupportedExtensions ? target.getSupportedExtensions.call(target) : []
          return Array.isArray(supported) ? supported.slice() : supported
        }, 'getSupportedExtensions')
      }

      const value = Reflect.get(target, prop, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })

  contextProxyMap.set(context, proxy)

  return proxy
}

function patchGetContext(prototype, originalGetContext, fingerprint) {
  if (!prototype || typeof originalGetContext !== 'function') {
    return
  }

  defineMethod(prototype, 'getContext', markNativeCode(function getContext(type, attributes) {
    const context = originalGetContext.call(this, type, attributes)
    if (!isWebGLContextType(type)) {
      return context
    }
    return createProxyForContext(context, fingerprint)
  }, 'getContext'))
}

export function installWebGLSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()

  if (runtime.modules.webgl) {
    return
  }

  patchGetContext(runtime.nativeRefs.canvasPrototype, runtime.nativeRefs.canvasGetContext, fingerprint)
  patchGetContext(runtime.nativeRefs.offscreenPrototype, runtime.nativeRefs.offscreenGetContext, fingerprint)

  markModule('webgl')
}