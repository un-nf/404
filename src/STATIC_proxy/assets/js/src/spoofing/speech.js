import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { findDescriptor, replaceGetter, mapMethod } from '../core/descriptors.js'

export function installSpeechSpoof() {
  const synth = globalThis.speechSynthesis
  const prototype = globalThis.SpeechSynthesisVoice?.prototype
  if (!synth || !prototype) { markModule('speech', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  const metadata = new WeakMap()
  const fields = ['name', 'voiceURI', 'lang', 'localService', 'default']
  const getters = Object.fromEntries(fields.map((key) => [key, findDescriptor(prototype, key)?.descriptor.get]))
  if (fields.some((key) => !getters[key] || !findDescriptor(prototype, key).descriptor.configurable)) {
    markModule('speech', { status: 'native', detail: 'voice descriptors cannot be normalized' }); return
  }
  for (const key of fields) replaceGetter(prototype, key, (value, voice) => metadata.get(voice)?.[key] ?? value)
  const languages = fp.speech_languages ?? [Array.isArray(fp.languages) ? fp.languages[0] : fp.language || 'en-US']
  const configured = fp.speech_voices ?? []
  const changed = mapMethod(synth, 'getVoices', (voices) => {
    const selected = []
    const counts = new Map()
    for (const voice of voices) {
      const lang = Reflect.apply(getters.lang, voice, [])
      const local = Reflect.apply(getters.localService, voice, [])
      if (!languages.includes(lang) || !local) continue
      const index = counts.get(lang) || 0
      if (index >= (fp.speech_voice_limit ?? 2)) continue
      const advertised = configured.filter((entry) => entry.lang === lang)[index]
      metadata.set(voice, {
        name: advertised?.name ?? `${lang} Voice ${index + 1}`,
        voiceURI: advertised?.voiceURI ?? `urn:voice:${lang}:${index + 1}`,
        lang, localService: true, default: selected.length === 0,
      })
      counts.set(lang, index + 1)
      selected.push(voice)
    }
    return selected
  })
  markModule('speech', { status: changed ? 'partial' : 'native',
    detail: 'bounded local native voices, normalized metadata; availability/loading timing observable' })
}
