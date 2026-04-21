import { isChromiumLike } from '../core/browser.js'
import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'

const BASE_WINDOW_GLOBALS = [
  '__STATIC_RUNTIME__',
  '__STATIC_CSP_NONCE',
  'fetch',
  'createImageBitmap',
  'Notification',
]

function getWindowGlobals(fingerprint) {
  const globals = BASE_WINDOW_GLOBALS.slice()
  if (isChromiumLike(fingerprint)) {
    globals.push('chrome')
  }
  return globals
}

function isSafeFrame(frame) {
  try {
    const src = frame.getAttribute('src') || frame.src || ''
    if (!src || src === 'about:blank' || src === 'about:srcdoc') {
      return true
    }
    return new URL(src, location.href).origin === location.origin
  } catch {
    return true
  }
}

function copyPrototypeDescriptors(source, target) {
  if (!source || !target || source === target) {
    return
  }
  for (const key of Object.getOwnPropertyNames(source)) {
    if (key === 'constructor') {
      continue
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, key)
    if (!descriptor) {
      continue
    }
    try {
      Object.defineProperty(target, key, descriptor)
    } catch {
      // ignore
    }
  }
}

function copyOwnDescriptor(source, target, key) {
  if (!source || !target) {
    return
  }
  const descriptor = Object.getOwnPropertyDescriptor(source, key)
  if (!descriptor) {
    return
  }
  try {
    Object.defineProperty(target, key, descriptor)
  } catch {
    // ignore
  }
}

function copyWindowGlobals(parentWindow, childWindow, fingerprint) {
  for (const key of getWindowGlobals(fingerprint)) {
    copyOwnDescriptor(parentWindow, childWindow, key)
  }
}

function copyPrototypeFromInstance(parentValue, childValue) {
  if (!parentValue || !childValue) {
    return
  }
  copyPrototypeDescriptors(Object.getPrototypeOf(parentValue), Object.getPrototypeOf(childValue))
}

function copyPrototypeDirect(parentPrototype, childPrototype) {
  if (!parentPrototype || !childPrototype) {
    return
  }
  copyPrototypeDescriptors(parentPrototype, childPrototype)
}

function propagate(frame) {
  try {
    if (!isSafeFrame(frame)) {
      return
    }

    const childWindow = frame.contentWindow
    if (!childWindow || childWindow === window) {
      return
    }

    const runtime = getRuntime()
    const fingerprint = getFingerprint()
    Object.defineProperty(childWindow, '__STATIC_RUNTIME__', {
      value: runtime,
      configurable: true,
      enumerable: false,
      writable: true,
    })
    Object.defineProperty(childWindow, '__STATIC_CSP_NONCE', {
      value: runtime.nonce,
      configurable: true,
      enumerable: false,
      writable: true,
    })

    copyWindowGlobals(window, childWindow, fingerprint)

    copyPrototypeFromInstance(window.navigator, childWindow.navigator)
    copyPrototypeFromInstance(window.screen, childWindow.screen)
    copyPrototypeFromInstance(window.document, childWindow.document)
    copyPrototypeDirect(window.HTMLElement?.prototype, childWindow.HTMLElement?.prototype)
    copyPrototypeDirect(window.HTMLCanvasElement?.prototype, childWindow.HTMLCanvasElement?.prototype)
    copyPrototypeDirect(window.CanvasRenderingContext2D?.prototype, childWindow.CanvasRenderingContext2D?.prototype)
    copyPrototypeDirect(window.OffscreenCanvas?.prototype, childWindow.OffscreenCanvas?.prototype)
    copyPrototypeDirect(window.Event?.prototype, childWindow.Event?.prototype)
    copyPrototypeDirect(window.RTCPeerConnection?.prototype || window.webkitRTCPeerConnection?.prototype, childWindow.RTCPeerConnection?.prototype || childWindow.webkitRTCPeerConnection?.prototype)
    copyPrototypeDirect(window.MediaStream?.prototype, childWindow.MediaStream?.prototype)
    copyPrototypeDirect(window.MediaStreamTrack?.prototype, childWindow.MediaStreamTrack?.prototype)
    copyPrototypeDirect(window.AnalyserNode?.prototype, childWindow.AnalyserNode?.prototype)
    copyPrototypeDirect(window.BaseAudioContext?.prototype || window.AudioContext?.prototype || window.webkitAudioContext?.prototype, childWindow.BaseAudioContext?.prototype || childWindow.AudioContext?.prototype || childWindow.webkitAudioContext?.prototype)
    copyPrototypeDirect(window.OfflineAudioContext?.prototype || window.webkitOfflineAudioContext?.prototype, childWindow.OfflineAudioContext?.prototype || childWindow.webkitOfflineAudioContext?.prototype)
    copyPrototypeDirect(window.AudioWorkletNode?.prototype, childWindow.AudioWorkletNode?.prototype)
    copyPrototypeFromInstance(window.navigator?.mediaDevices, childWindow.navigator?.mediaDevices)
    copyPrototypeFromInstance(window.speechSynthesis, childWindow.speechSynthesis)
  } catch {
    // ignore
  }
}

export function installIframePropagation() {
  document.querySelectorAll('iframe').forEach((frame) => {
    frame.addEventListener('load', () => propagate(frame), { once: true })
    if (frame.contentDocument?.readyState === 'complete') {
      propagate(frame)
    }
  })

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node instanceof HTMLIFrameElement) {
          node.addEventListener('load', () => propagate(node), { once: true })
        }
      }
    }
  })
  observer.observe(document.documentElement, { childList: true, subtree: true })

  markModule('iframePropagation')
}