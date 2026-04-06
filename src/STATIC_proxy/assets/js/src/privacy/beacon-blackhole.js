import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const DEFAULT_RULES = [
  { hostSuffix: 'play.google.com', pathPrefix: '/log' },
]

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function matchesRule(url, rules) {
  try {
    const parsed = new URL(url)
    return rules.some((rule) => {
      const hostMatches = !rule.hostSuffix || parsed.hostname.endsWith(rule.hostSuffix)
      const pathMatches = !rule.pathPrefix || parsed.pathname.startsWith(rule.pathPrefix)
      return hostMatches && pathMatches
    })
  } catch {
    return false
  }
}

function dispatchXhrLifecycle(xhr) {
  const EventCtor = window.Event
  const fire = (type, handlerName) => {
    try {
      if (typeof xhr.dispatchEvent === 'function' && typeof EventCtor === 'function') {
        xhr.dispatchEvent(new EventCtor(type))
      }
    } catch {
      // ignore
    }
    try {
      if (typeof xhr[handlerName] === 'function') {
        xhr[handlerName].call(xhr)
      }
    } catch {
      // ignore
    }
  }

  fire('readystatechange', 'onreadystatechange')
  fire('load', 'onload')
  fire('loadend', 'onloadend')
}

function finalizeBlockedXhr(xhr, url) {
  try {
    Object.defineProperty(xhr, 'readyState', {
      value: 4,
      configurable: true,
    })
  } catch {
    // ignore
  }
  try {
    Object.defineProperty(xhr, 'status', {
      value: 204,
      configurable: true,
    })
  } catch {
    // ignore
  }
  try {
    Object.defineProperty(xhr, 'statusText', {
      value: 'No Content',
      configurable: true,
    })
  } catch {
    // ignore
  }
  try {
    Object.defineProperty(xhr, 'responseURL', {
      value: url,
      configurable: true,
    })
  } catch {
    // ignore
  }
  try {
    Object.defineProperty(xhr, 'responseText', {
      value: '',
      configurable: true,
    })
  } catch {
    // ignore
  }
  try {
    Object.defineProperty(xhr, 'response', {
      value: '',
      configurable: true,
    })
  } catch {
    // ignore
  }

  queueMicrotask(() => dispatchXhrLifecycle(xhr))
}

export function installBeaconBlackhole() {
  const runtime = getRuntime()
  const extraRules = Array.isArray(runtime.config?.raw?.privacy_rules) ? runtime.config.raw.privacy_rules : []
  const rules = DEFAULT_RULES.concat(extraRules)
  const xhrUrls = new WeakMap()
  if (runtime.modules.beaconBlackhole) {
    return
  }

  if (runtime.nativeRefs.fetch) {
    defineMethod(window, 'fetch', markNativeCode(function fetch(input, init) {
      const url = typeof input === 'string' ? input : input?.url
      if (url && matchesRule(url, rules)) {
        return Promise.resolve(new runtime.nativeRefs.response('', { status: 204 }))
      }
      return runtime.nativeRefs.fetch(input, init)
    }, 'fetch'))
  }

  if (runtime.nativeRefs.sendBeacon) {
    defineMethod(runtime.nativeRefs.NavigatorPrototype, 'sendBeacon', markNativeCode(function sendBeacon(url, data) {
      if (matchesRule(url, rules)) {
        return true
      }
      return runtime.nativeRefs.sendBeacon(url, data)
    }, 'sendBeacon'))
  }

  if (runtime.nativeRefs.xhrOpen && runtime.nativeRefs.xhrSend) {
    defineMethod(runtime.nativeRefs.xhrPrototype, 'open', markNativeCode(function open(method, url) {
      xhrUrls.set(this, String(url || ''))
      return runtime.nativeRefs.xhrOpen.apply(this, arguments)
    }, 'open'))

    defineMethod(runtime.nativeRefs.xhrPrototype, 'send', markNativeCode(function send(body) {
      const url = xhrUrls.get(this) || ''
      if (url && matchesRule(url, rules)) {
        finalizeBlockedXhr(this, url)
        return undefined
      }
      return runtime.nativeRefs.xhrSend.call(this, body)
    }, 'send'))
  }

  markModule('beaconBlackhole')
}