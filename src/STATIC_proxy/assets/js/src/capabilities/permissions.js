import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter, replaceMethod } from '../core/descriptors.js'

const DENIED = new Set(['notifications', 'push', 'geolocation', 'camera', 'microphone',
  'background-sync', 'clipboard-read', 'clipboard-write'])

export function permissionObservation(name, nativeState, fp) {
  if (name === 'persistent-storage') return nativeState
  if (name === 'geolocation' && fp.enable_geolocation_spoof === false) return nativeState
  const configured = fp.permission_states?.[name]
  return configured === 'native' ? nativeState : configured ?? (DENIED.has(name) ? 'denied' : 'prompt')
}

export function installPermissions() {
  const permissions = navigator.permissions
  if (!permissions) { markModule('permissions', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  const names = new WeakMap()
  const state = replaceGetter(globalThis.PermissionStatus?.prototype, 'state', (value, status) =>
    names.has(status) ? permissionObservation(names.get(status), value, fp) : value)
  const query = state && replaceMethod(permissions, 'query', (native, receiver, args) => {
    let name
    const descriptor = args[0]
    const converted = descriptor && (typeof descriptor === 'object' || typeof descriptor === 'function')
      ? new Proxy({}, { get(_target, key) {
        const value = Reflect.get(descriptor, key, descriptor)
        // Convert once during the native dictionary read; do not pre-read input.
        if (key === 'name') { name = `${value}`; return name }
        return value
      } }) : descriptor
    return Reflect.apply(native, receiver, [converted, ...args.slice(1)]).then((status) => {
      names.set(status, name)
      return status
    })
  })
  markModule('permissions', { status: query ? 'partial' : 'native',
    detail: 'masked native PermissionStatus; browser grants and native events remain' })
}
