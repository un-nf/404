import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { findDescriptor, replaceMethod, mapMethod } from '../core/descriptors.js'
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
  const configuredStride = imageData.width <= noiseConfig.small_canvas_threshold && imageData.height <= noiseConfig.small_canvas_threshold
    ? noiseConfig.small_canvas_stride
    : noiseConfig.default_stride
  const stride = Math.max(4, Math.ceil(configuredStride / 4) * 4)

  for (let index = 0; index < imageData.data.length; index += stride) {
    if (!noiseConfig.touch_alpha && imageData.data[index + 3] === 0) continue
    if (rng() >= noiseConfig.noise_probability) {
      continue
    }

    const magnitude = noiseConfig.delta_min + ((noiseConfig.delta_max - noiseConfig.delta_min) * rng())
    const signed = (rng() >= 0.5 ? 1 : -1) * magnitude
    const delta = noiseConfig.integer_delta ? Math.round(signed) : signed
    const adjust = (value) => imageData.data.BYTES_PER_ELEMENT === 1 ? clampByte(value + delta) : value + delta / 255

    imageData.data[index] = adjust(imageData.data[index])
    if (index + 1 < imageData.data.length) {
      imageData.data[index + 1] = adjust(imageData.data[index + 1])
    }
    if (index + 2 < imageData.data.length) {
      imageData.data[index + 2] = adjust(imageData.data[index + 2])
    }
    if (noiseConfig.touch_alpha && index + 3 < imageData.data.length) {
      imageData.data[index + 3] = adjust(imageData.data[index + 3])
    }
  }
}


export function installCanvasSpoof() {
  const runtime=getRuntime(), fingerprint=getFingerprint(), noiseConfig=normalizeNoiseConfig(fingerprint)
  const HTML=globalThis.HTMLCanvasElement, Offscreen=globalThis.OffscreenCanvas
  const htmlProto=HTML?.prototype, offProto=Offscreen?.prototype
  const Context=globalThis.CanvasRenderingContext2D
  let offContextProto=globalThis.OffscreenCanvasRenderingContext2D?.prototype
  if(!offContextProto&&Offscreen) {
    try {
      const probe=new Offscreen(1,1).getContext('2d')
      if(probe)offContextProto=Object.getPrototypeOf(probe)
    } catch { /* Optional 2D support must not abort the other canvas surfaces. */ }
  }
  const nativeRead=Context?.prototype.getImageData, offRead=offContextProto?.getImageData
  const nativePut=Context?.prototype.putImageData, offPut=offContextProto?.putImageData
  const create=globalThis.Document?.prototype.createElement
  const bitmap=globalThis.createImageBitmap
  const transfer=offProto?.transferToImageBitmap
  function noisyCopy(source, prototype) {
    // Native width/height accessors validate the receiver without calling an
    // export twice, and without binding the drawing surface to a new context.
    const width=Reflect.apply(findDescriptor(prototype,'width').descriptor.get,source,[])
    const height=Reflect.apply(findDescriptor(prototype,'height').descriptor.get,source,[])
    if(!width||!height)return source
    const copy=prototype===offProto?new Offscreen(width,height):Reflect.apply(create,document,['canvas'])
    copy.width=width;copy.height=height
    const context=copy.getContext('2d')
    context.drawImage(source,0,0)
    try {
      const read=prototype===offProto?offRead:nativeRead,put=prototype===offProto?offPut:nativePut
      const image=Reflect.apply(read,context,[0,0,width,height])
      injectCanvasNoise(image,runtime,fingerprint,noiseConfig,'pixels')
      Reflect.apply(put,context,[image,0,0])
      return copy
    } catch(error) {
      // Tainted data remains tainted: the genuine export supplies its native
      // error/rejection. Never swallow/repeat the application's export call.
      if(error.name==='SecurityError')return source
      throw error
    }
  }
  for(const prototype of [Context?.prototype,offContextProto]) {
    mapMethod(prototype,'getImageData',image=>{injectCanvasNoise(image,runtime,fingerprint,noiseConfig,'pixels');return image})
  }
  for(const [prototype,name]of [[htmlProto,'toDataURL'],[htmlProto,'toBlob'],[offProto,'convertToBlob']]) {
    if(prototype===offProto&&(!offRead||!offPut))continue
    replaceMethod(prototype,name,(native,receiver,args)=>Reflect.apply(native,noisyCopy(receiver,prototype),args))
  }
  if(transfer&&offRead&&offPut)mapMethod(offProto,'transferToImageBitmap',original=>{
    // Transfer the original once so its clearing/ownership semantics survive.
    const copy=new Offscreen(original.width,original.height),context=copy.getContext('2d')
    context.drawImage(original,0,0)
    const image=Reflect.apply(offRead,context,[0,0,original.width,original.height])
    injectCanvasNoise(image,runtime,fingerprint,noiseConfig,'pixels')
    Reflect.apply(offPut,context,[image,0,0])
    const result=Reflect.apply(transfer,copy,[]);original.close();return result
  })
  if(bitmap&&Offscreen&&offRead&&offPut)mapMethod(globalThis,'createImageBitmap',promise=>promise.then(original=>{
    const copy=new Offscreen(original.width,original.height),context=copy.getContext('2d')
    context.drawImage(original,0,0)
    const image=Reflect.apply(offRead,context,[0,0,original.width,original.height])
    injectCanvasNoise(image,runtime,fingerprint,noiseConfig,'pixels')
    Reflect.apply(offPut,context,[image,0,0])
    return Reflect.apply(bitmap,globalThis,[copy]).then(result=>{original.close();return result})
  }))
  markModule('canvas',{status:'partial',detail:'native readback and isolated export copies; originals never temporarily painted; color/rectangle and rendering inference require measurement'})
}
