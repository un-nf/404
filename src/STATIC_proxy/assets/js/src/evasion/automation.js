import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const AUTOMATION_GLOBALS = [
  '__webdriver_script_fn',
  '__driver_evaluate',
  '__webdriver_evaluate',
  '__selenium_evaluate',
  '__fxdriver_evaluate',
  '__driver_unwrapped',
  '__webdriver_unwrapped',
  '__selenium_unwrapped',
  '__fxdriver_unwrapped',
  '_phantom',
  '__nightmare',
  'callPhantom',
  '_selenium',
  'callSelenium',
  '_Selenium_IDE_Recorder',
  '__webdriverFunc',
]

export function installAutomationEvasion() {
  const fingerprint = getFingerprint()
  const isFirefox = (fingerprint.browser_type || 'chrome') === 'firefox'

  Object.defineProperty(Navigator.prototype, 'webdriver', {
    get: markNativeCode(function webdriver() {
      return false
    }, 'webdriver'),
    configurable: true,
    enumerable: true,
  })

  Object.defineProperty(Document.prototype, 'hasFocus', {
    value: markNativeCode(function hasFocus() {
      return true
    }, 'hasFocus'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  Object.defineProperty(Document.prototype, 'visibilityState', {
    get: markNativeCode(function visibilityState() {
      return 'visible'
    }, 'visibilityState'),
    configurable: true,
    enumerable: true,
  })

  Object.defineProperty(Document.prototype, 'hidden', {
    get: markNativeCode(function hidden() {
      return false
    }, 'hidden'),
    configurable: true,
    enumerable: true,
  })

  if (!isFirefox) {
    if (!window.chrome) {
      window.chrome = {
        app: { isInstalled: false },
        csi: markNativeCode(function csi() { return {} }, 'csi'),
        loadTimes: markNativeCode(function loadTimes() { return {} }, 'loadTimes'),
        runtime: {},
      }
    }
  } else {
    try {
      delete window.chrome
    } catch {
      // ignore
    }
  }

  for (const key of AUTOMATION_GLOBALS) {
    try {
      if (key in window) {
        delete window[key]
      }
    } catch {
      // ignore
    }
  }

  markModule('automation')
}