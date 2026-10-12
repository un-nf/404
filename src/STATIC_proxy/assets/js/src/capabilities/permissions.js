import { markModule } from '../core/guard.js'

export function installPermissions() {
  // This interface controls real operations or native exotic collections.
  // Preserve the browser implementation instead of inventing its capabilities.
  markModule('permissions', { status: Boolean(navigator.permissions) ? 'native' : 'unavailable',
    detail: 'native interface retained; synthetic persona model unsupported' })
}
