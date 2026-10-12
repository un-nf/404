import { markModule } from '../core/guard.js'

export function installSpeechSpoof() {
  // Only browser-created voices can be assigned to a native utterance.
  // Keep asynchronous loading, event handlers and selection operational.
  markModule('speech', { status: globalThis.speechSynthesis ? 'native' : 'unavailable',
    detail: 'usable native voices retained; virtual voice inventory unsupported' })
}
