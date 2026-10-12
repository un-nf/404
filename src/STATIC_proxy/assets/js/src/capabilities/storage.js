import { markModule } from '../core/guard.js'

export function installStorage() {
  // A synthetic quota cannot change actual allocation or durability guarantees.
  markModule('storage', { status: navigator.storage ? 'native' : 'unavailable',
    detail: 'native quota, persistence and functional methods retained' })
}
