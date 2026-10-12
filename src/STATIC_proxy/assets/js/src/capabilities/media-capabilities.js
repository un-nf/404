import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { mapMethod } from '../core/descriptors.js'

export function normalizeMediaCapability(result, fp) {
  // MediaCapabilitiesInfo is a WebIDL dictionary; a plain object is its native
  // shape. Keep real codec/DRM support but mask hardware-dependent performance.
  return { ...result,
    smooth: result.supported && (fp.media_capabilities?.smooth ?? true),
    powerEfficient: result.supported && (fp.media_capabilities?.power_efficient ?? true) }
}

export function installMediaCapabilities() {
  const capabilities = navigator.mediaCapabilities
  if (!capabilities) { markModule('mediaCapabilities', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  let installed = 0
  for (const key of ['decodingInfo', 'encodingInfo']) {
    installed += Number(mapMethod(capabilities, key, (promise) =>
      promise.then((result) => normalizeMediaCapability(result, fp))))
  }
  markModule('mediaCapabilities', { status: installed ? 'partial' : 'native',
    detail: 'masked hardware hints; native codec/DRM support and validation' })
}
