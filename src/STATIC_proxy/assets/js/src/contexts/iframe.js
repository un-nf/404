import { getConfig } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { findDescriptor, replaceGetter } from '../core/descriptors.js'

export function installIframePropagation(initializeChild) {
  const runtime = getRuntime()
  const watched = new WeakSet()
  const busy = new WeakSet()
  const prototype = globalThis.HTMLIFrameElement?.prototype
  const windowGetter = findDescriptor(prototype, 'contentWindow')?.descriptor.get
  const documentGetter = findDescriptor(prototype, 'contentDocument')?.descriptor.get
  runtime.frames = new WeakMap()

  function propagate(frame) {
    if (busy.has(frame)) return
    busy.add(frame)
    let outcome = 'unavailable'
    try {
      const child = windowGetter ? Reflect.apply(windowGetter, frame, []) : frame.contentWindow
      const doc = documentGetter ? Reflect.apply(documentGetter, frame, []) : frame.contentDocument
      if (child && child !== window && doc) {
        // Proxied documents own their parser-inserted bootstrap. Avoid
        // installing a second set of wrappers over that document.
        const hasBootstrap = Array.from(doc.scripts).some((script) => {
          try {
            return new URL(script.src, doc.baseURI).pathname === '/__static/runtime.js'
          } catch {
            return false
          }
        })
        outcome = hasBootstrap ? 'document-bootstrap-unverified' :
          typeof initializeChild === 'function' ? initializeChild(child, doc, getConfig().raw) : 'unsupported'
      }
    } catch {
      outcome = 'unavailable'
    }
    runtime.frames.set(frame, outcome)
    busy.delete(frame)
  }

  function watch(frame) {
    if (!watched.has(frame)) {
      watched.add(frame)
      frame.addEventListener('load', () => propagate(frame))
    }
    propagate(frame)
  }

  for (const name of ['contentWindow', 'contentDocument']) {
    replaceGetter(prototype, name, (value, frame) => {
      propagate(frame)
      return value
    })
  }
  document.querySelectorAll('iframe').forEach(watch)
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== 1) continue
        if (node.localName === 'iframe') watch(node)
        node.querySelectorAll?.('iframe').forEach(watch)
      }
    }
  })
  observer.observe(document.documentElement, { childList: true, subtree: true })
  markModule('iframePropagation', { status: 'partial', detail: 'synchronous accessible-frame getters and observer/load fallback; early child code and CSP gaps remain' })
}
