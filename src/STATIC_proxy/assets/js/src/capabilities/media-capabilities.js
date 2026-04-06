import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

export function installMediaCapabilities() {
  const mediaCapabilities = Object.freeze({
    decodingInfo: markNativeCode(async function decodingInfo(configuration) {
      return {
        configuration,
        keySystemAccess: null,
        powerEfficient: true,
        smooth: true,
        supported: true,
      }
    }, 'decodingInfo'),
    encodingInfo: markNativeCode(async function encodingInfo(configuration) {
      return {
        configuration,
        powerEfficient: true,
        smooth: true,
        supported: true,
      }
    }, 'encodingInfo'),
  })

  Object.defineProperty(Navigator.prototype, 'mediaCapabilities', {
    get: markNativeCode(function mediaCapabilitiesGetter() {
      return mediaCapabilities
    }, 'mediaCapabilities'),
    configurable: true,
    enumerable: true,
  })

  markModule('mediaCapabilities')
}