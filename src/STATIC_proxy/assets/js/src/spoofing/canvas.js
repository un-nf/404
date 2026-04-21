import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const canvasSnapshotMap = new WeakMap()

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

const DEFAULT_NOISE = {
  small_canvas_threshold: 16,
  small_canvas_stride: 20,
  default_stride: 10,
  noise_probability: 0.1,
  delta_min: 1,
  delta_max: 1,
  integer_delta: true,
  touch_alpha: false,
}

const CANVAS_SIGNATURE_SAMPLES = 32

function normalizeNoiseConfig(fingerprint) {
  return {
    ...DEFAULT_NOISE,
    ...(fingerprint.canvas_noise || {}),
  }
}

function clampByte(value) {
  if (value < 0) {
    return 0
  }
  if (value > 255) {
    return 255
  }
  return value
}

function resolveOriginKey(runtime) {
  if (runtime.entropy?.origin) {
    return runtime.entropy.origin
  }

  try {
    return location.origin
  } catch {
    return 'opaque'
  }
}

function buildCanvasContentSignature(imageData, runtime, scopeLabel) {
  const bytes = imageData?.data
  const width = imageData?.width || 0
  const height = imageData?.height || 0

  if (!bytes?.length || width <= 0 || height <= 0) {
    return `${scopeLabel}:${width}x${height}:empty`
  }

  const targetSamples = Math.max(1, Math.min(CANVAS_SIGNATURE_SAMPLES, Math.floor(bytes.length / 4)))
  const stride = Math.max(4, Math.floor(bytes.length / targetSamples / 4) * 4)
  let signature = 0x811c9dc5

  for (let index = 0; index < bytes.length; index += stride) {
    signature = runtime.entropy.hash(
      `${signature}:${bytes[index] || 0}:${bytes[index + 1] || 0}:${bytes[index + 2] || 0}:${bytes[index + 3] || 0}`,
    )
  }

  const lastIndex = Math.max(0, bytes.length - 4)
  signature = runtime.entropy.hash(
    `${signature}:${bytes[lastIndex] || 0}:${bytes[lastIndex + 1] || 0}:${bytes[lastIndex + 2] || 0}:${bytes[lastIndex + 3] || 0}`,
  )

  return `${scopeLabel}:${width}x${height}:${signature.toString(16)}`
}

function createNoiseRng(runtime, fingerprint, imageData, seedLabel) {
  const scope = resolveOriginKey(runtime)
  const signature = buildCanvasContentSignature(imageData, runtime, `${scope}:${seedLabel}`)
  const seed = runtime.entropy.hash(`${fingerprint.canvas_hash || 'static'}:${runtime.entropy.sessionId}:${signature}`)
  return runtime.entropy.rng(seed)
}

function injectCanvasNoise(imageData, runtime, fingerprint, noiseConfig, seedLabel = 'canvas') {
  if (!imageData?.data) {
    return
  }

  const rng = createNoiseRng(runtime, fingerprint, imageData, seedLabel)
  const stride = imageData.width <= noiseConfig.small_canvas_threshold && imageData.height <= noiseConfig.small_canvas_threshold
    ? noiseConfig.small_canvas_stride
    : noiseConfig.default_stride

  for (let index = 0; index < imageData.data.length; index += stride) {
    if (rng() >= noiseConfig.noise_probability) {
      continue
    }

    const magnitude = noiseConfig.delta_min + ((noiseConfig.delta_max - noiseConfig.delta_min) * rng())
    const signed = (rng() >= 0.5 ? 1 : -1) * magnitude
    const delta = noiseConfig.integer_delta ? Math.round(signed) : signed

    imageData.data[index] = clampByte(imageData.data[index] + delta)
    if (index + 1 < imageData.data.length) {
      imageData.data[index + 1] = clampByte(imageData.data[index + 1] + delta)
    }
    if (index + 2 < imageData.data.length) {
      imageData.data[index + 2] = clampByte(imageData.data[index + 2] + delta)
    }
    if (noiseConfig.touch_alpha && index + 3 < imageData.data.length) {
      imageData.data[index + 3] = clampByte(imageData.data[index + 3] + delta)
    }
  }
}

function cloneSnapshot(imageData) {
  return {
    data: new Uint8ClampedArray(imageData.data),
    width: imageData.width,
    height: imageData.height,
  }
}

function restoreSnapshot(context, snapshot, runtime) {
  try {
    const restored = runtime.nativeRefs.canvasGetImageData.call(context, 0, 0, snapshot.width, snapshot.height)
    restored.data.set(snapshot.data)
    runtime.nativeRefs.canvasPutImageData.call(context, restored, 0, 0)
  } catch {
    // ignore
  }
}

function withCanvasExportNoise(canvasLike, runtime, fingerprint, noiseConfig, operation, seedLabel = 'export') {
  if (!canvasLike || typeof canvasLike.getContext !== 'function') {
    return operation()
  }

  try {
    const context = canvasLike.getContext('2d')
    if (!context || !runtime.nativeRefs.canvasGetImageData || !runtime.nativeRefs.canvasPutImageData) {
      return operation()
    }

    const imageData = runtime.nativeRefs.canvasGetImageData.call(context, 0, 0, canvasLike.width || 0, canvasLike.height || 0)
    const snapshot = cloneSnapshot(imageData)
    canvasSnapshotMap.set(canvasLike, snapshot)
    injectCanvasNoise(imageData, runtime, fingerprint, noiseConfig, seedLabel)
    runtime.nativeRefs.canvasPutImageData.call(context, imageData, 0, 0)

    let result
    try {
      result = operation()
    } catch (error) {
      restoreSnapshot(context, snapshot, runtime)
      canvasSnapshotMap.delete(canvasLike)
      throw error
    }

    if (result && typeof result.finally === 'function') {
      return result.finally(() => {
        restoreSnapshot(context, snapshot, runtime)
        canvasSnapshotMap.delete(canvasLike)
      })
    }

    restoreSnapshot(context, snapshot, runtime)
    canvasSnapshotMap.delete(canvasLike)
    return result
  } catch {
    return operation()
  }
}

function exposeLegacyFingerprint(runtime, fingerprint) {
  if ('__404_canvas_fingerprint' in window) {
    return
  }

  const value = `${fingerprint.canvas_hash || 'static'}:${runtime.entropy.sessionId}`
  try {
    Object.defineProperty(window, '__404_canvas_fingerprint', {
      value: `${value}:${resolveOriginKey(runtime)}`,
      writable: false,
      enumerable: false,
      configurable: false,
    })
  } catch {
    // ignore
  }
}

export function installCanvasSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  const noiseConfig = normalizeNoiseConfig(fingerprint)

  if (runtime.modules.canvas) {
    return
  }

  exposeLegacyFingerprint(runtime, fingerprint)

  if (runtime.nativeRefs.canvasGetImageData) {
    defineMethod(runtime.nativeRefs.canvas2dPrototype, 'getImageData', markNativeCode(function getImageData(sx, sy, sw, sh) {
      const imageData = runtime.nativeRefs.canvasGetImageData.call(this, sx, sy, sw, sh)
      injectCanvasNoise(imageData, runtime, fingerprint, noiseConfig, `readback:${sx || 0},${sy || 0},${sw || 0},${sh || 0}`)
      return imageData
    }, 'getImageData'))
  }

  if (runtime.nativeRefs.canvasToDataURL) {
    defineMethod(runtime.nativeRefs.canvasPrototype, 'toDataURL', markNativeCode(function toDataURL() {
      return withCanvasExportNoise(this, runtime, fingerprint, noiseConfig, () => runtime.nativeRefs.canvasToDataURL.apply(this, arguments), 'toDataURL')
    }, 'toDataURL'))

    if (runtime.nativeRefs.canvasToBlob) {
      defineMethod(runtime.nativeRefs.canvasPrototype, 'toBlob', markNativeCode(function toBlob(callback, type, quality) {
        const args = arguments
        return withCanvasExportNoise(this, runtime, fingerprint, noiseConfig, () => runtime.nativeRefs.canvasToBlob.call(this, function blobCallback() {
          return typeof callback === 'function' ? callback.apply(this, arguments) : undefined
        }, args[1], args[2]), 'toBlob')
      }, 'toBlob'))
    }
  }

  if (runtime.nativeRefs.offscreenPrototype) {
    if (runtime.nativeRefs.offscreenConvertToBlob) {
      defineMethod(runtime.nativeRefs.offscreenPrototype, 'convertToBlob', markNativeCode(function convertToBlob() {
        return withCanvasExportNoise(this, runtime, fingerprint, noiseConfig, () => runtime.nativeRefs.offscreenConvertToBlob.apply(this, arguments), 'convertToBlob')
      }, 'convertToBlob'))
    }

    if (runtime.nativeRefs.offscreenTransferToImageBitmap) {
      defineMethod(runtime.nativeRefs.offscreenPrototype, 'transferToImageBitmap', markNativeCode(function transferToImageBitmap() {
        return withCanvasExportNoise(this, runtime, fingerprint, noiseConfig, () => runtime.nativeRefs.offscreenTransferToImageBitmap.apply(this, arguments), 'transferToImageBitmap')
      }, 'transferToImageBitmap'))
    }
  }

  if (runtime.nativeRefs.createImageBitmap) {
    defineMethod(window, 'createImageBitmap', markNativeCode(function createImageBitmap(source) {
      if (source && typeof source === 'object' && 'width' in source && 'height' in source) {
        return withCanvasExportNoise(source, runtime, fingerprint, noiseConfig, () => runtime.nativeRefs.createImageBitmap.apply(window, arguments), 'createImageBitmap')
      }
      return runtime.nativeRefs.createImageBitmap.apply(window, arguments)
    }, 'createImageBitmap'))
  }

  markModule('canvas')
}