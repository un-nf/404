import { markModule } from '../core/guard.js'

export function installNotifications() {
  // This interface controls real operations or native exotic collections.
  // Preserve the browser implementation instead of inventing its capabilities.
  markModule('notifications', { status: typeof globalThis.Notification === 'function' ? 'native' : 'unavailable',
    detail: 'native interface retained; synthetic persona model unsupported' })
}
