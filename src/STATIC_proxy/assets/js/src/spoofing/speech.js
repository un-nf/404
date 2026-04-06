import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function normalizeLanguages(fingerprint) {
  if (Array.isArray(fingerprint.languages)) {
    return fingerprint.languages.slice()
  }
  if (typeof fingerprint.languages === 'string') {
    return fingerprint.languages.split(',').map((value) => value.trim()).filter(Boolean)
  }
  return [fingerprint.language || 'en-US']
}

export function installSpeechSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  const synth = runtime.nativeRefs.speechSynthesis
  const prototype = runtime.nativeRefs.speechSynthesisPrototype
  if (!synth || !prototype || runtime.modules.speech) {
    return
  }

  const primaryLanguage = normalizeLanguages(fingerprint)[0] || 'en-US'
  const configuredVoices = Array.isArray(fingerprint.speech_voices) ? fingerprint.speech_voices : []
  const baseVoices = configuredVoices.length > 0 ? configuredVoices : [
    { name: 'Google US English', lang: primaryLanguage, localService: true, default: true, voiceURI: 'Google US English' },
  ]
  const voices = baseVoices.map((voice, index) => Object.freeze({
    default: Boolean(voice.default && index === 0),
    lang: voice.lang || primaryLanguage,
    localService: voice.localService !== false,
    name: voice.name || `Static Voice ${index + 1}`,
    voiceURI: voice.voiceURI || `${voice.name || 'static'}-${index}`,
  }))

  defineMethod(prototype, 'getVoices', markNativeCode(function getVoices() {
    return voices.slice()
  }, 'getVoices'))

  Object.defineProperty(prototype, 'onvoiceschanged', {
    configurable: true,
    enumerable: true,
    get: markNativeCode(function onvoiceschanged() {
      return null
    }, 'onvoiceschanged'),
    set: markNativeCode(function onvoiceschanged() {
      return undefined
    }, 'onvoiceschanged'),
  })

  markModule('speech')
}