import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function buildErrorObject() {
  return {
    code: 1,
    message: 'User denied Geolocation',
    PERMISSION_DENIED: 1,
    POSITION_UNAVAILABLE: 2,
    TIMEOUT: 3,
  }
}

export function installGeolocationDenial() {
  if (!navigator.geolocation) {
    return
  }

  Object.defineProperty(navigator.geolocation, 'getCurrentPosition', {
    value: markNativeCode(function getCurrentPosition(success, error) {
      if (typeof error === 'function') {
        setTimeout(() => error(buildErrorObject()), 0)
      }
    }, 'getCurrentPosition'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  Object.defineProperty(navigator.geolocation, 'watchPosition', {
    value: markNativeCode(function watchPosition(success, error) {
      if (typeof error === 'function') {
        setTimeout(() => error(buildErrorObject()), 0)
      }
      return 0
    }, 'watchPosition'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  Object.defineProperty(navigator.geolocation, 'clearWatch', {
    value: markNativeCode(function clearWatch() {}, 'clearWatch'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  markModule('geolocation')
}