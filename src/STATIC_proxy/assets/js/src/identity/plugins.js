import { markModule } from '../core/guard.js'

export function installPlugins() {
  // HTML standardizes PDF compatibility entries. Keep genuine exotic
  // PluginArray/MimeTypeArray objects; do not invent installed extensions.
  markModule('plugins', { status: Boolean(navigator.plugins) ? 'native' : 'unavailable',
    detail: 'standard PDF compatibility collection retained by deliberate policy' })
}
