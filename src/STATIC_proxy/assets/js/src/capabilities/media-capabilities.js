import { markModule } from '../core/guard.js'

export function installMediaCapabilities() {
  // This interface controls real operations or native exotic collections.
  // Preserve the browser implementation instead of inventing its capabilities.
  markModule('mediaCapabilities', { status: Boolean(navigator.mediaCapabilities) ? 'native' : 'unavailable',
    detail: 'native interface retained; synthetic persona model unsupported' })
}
