import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

export function installNotifications() {
  function Notification() {
    throw new DOMException('Permission denied', 'NotAllowedError')
  }

  markNativeCode(Notification, 'Notification')
  Object.defineProperty(Notification, 'permission', {
    value: 'denied',
    configurable: true,
    writable: false,
    enumerable: true,
  })
  Object.defineProperty(Notification, 'requestPermission', {
    value: markNativeCode(async function requestPermission() {
      return 'denied'
    }, 'requestPermission'),
    configurable: true,
    writable: true,
    enumerable: true,
  })

  window.Notification = Notification
  markModule('notifications')
}