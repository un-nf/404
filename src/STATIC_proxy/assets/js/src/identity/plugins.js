import { markModule } from '../core/guard.js'

export function installPlugins() {
  // This interface controls real operations or native exotic collections.
  // Preserve the browser implementation instead of inventing its capabilities.
  markModule('plugins', { status: Boolean(navigator.plugins) ? 'native' : 'unavailable',
    detail: 'native interface retained; synthetic persona model unsupported' })
}
