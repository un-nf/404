import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const DENIED = new Set([
  'notifications',
  'push',
  'geolocation',
  'camera',
  'microphone',
  'background-sync',
  'clipboard-read',
  'clipboard-write',
])

function createPermissionStatus(state) {
  return Object.freeze({
    state,
    onchange: null,
    addEventListener: markNativeCode(function addEventListener() {}, 'addEventListener'),
    removeEventListener: markNativeCode(function removeEventListener() {}, 'removeEventListener'),
    dispatchEvent: markNativeCode(function dispatchEvent() { return true }, 'dispatchEvent'),
  })
}

export function installPermissions() {
  const permissions = Object.freeze({
    query: markNativeCode(async function query(descriptor) {
      const name = descriptor?.name || ''
      const state = DENIED.has(name) ? 'denied' : 'prompt'
      return createPermissionStatus(state)
    }, 'query'),
  })

  Object.defineProperty(Navigator.prototype, 'permissions', {
    get: markNativeCode(function permissionsGetter() {
      return permissions
    }, 'permissions'),
    configurable: true,
    enumerable: true,
  })

  markModule('permissions')
}