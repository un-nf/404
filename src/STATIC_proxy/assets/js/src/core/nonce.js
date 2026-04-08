import { getRuntime } from './guard.js'

export function captureNonce() {
  const runtime = getRuntime()
  const currentScript = document.currentScript
  if (currentScript) {
    const nonce = currentScript.nonce || currentScript.getAttribute('nonce')
    if (nonce) {
      runtime.nonce = nonce
      return nonce
    }
  }

  const script = document.querySelector('script[nonce]')
  if (script) {
    const nonce = script.nonce || script.getAttribute('nonce')
    if (nonce) {
      runtime.nonce = nonce
      return nonce
    }
  }

  if (window.__STATIC_CSP_NONCE) {
    runtime.nonce = window.__STATIC_CSP_NONCE
    return runtime.nonce
  }

  runtime.nonce = null
  return null
}