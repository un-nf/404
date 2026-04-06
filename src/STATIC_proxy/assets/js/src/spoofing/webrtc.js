import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const PRIVATE_IPV4 = /^(0\.|10\.|127\.|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)/
const PRIVATE_IPV6 = /^(::1|fc00:|fd00:|fe80:)/i
const originalOnIceCandidateHandlers = new WeakMap()
const wrappedOnIceCandidateHandlers = new WeakMap()

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function sanitizeCandidateLine(line, fingerprint) {
  if (typeof line !== 'string') {
    return line
  }

  const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '104.244.72.1'
  const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:4860:4860::8888'
  const trimmed = line.trim()
  const prefixed = trimmed.startsWith('a=')
  const payload = prefixed ? trimmed.slice(2) : trimmed
  const parts = payload.split(' ')
  if (parts.length < 8) {
    return trimmed
  }

  const ipIndex = 4
  const typeIndex = parts.indexOf('typ')
  const ip = parts[ipIndex]
  const privateAddress = PRIVATE_IPV4.test(ip) || PRIVATE_IPV6.test(ip)
  if (PRIVATE_IPV4.test(ip)) {
    parts[ipIndex] = publicIpv4
  } else if (PRIVATE_IPV6.test(ip)) {
    parts[ipIndex] = publicIpv6
  }

  if (typeIndex >= 0 && privateAddress && parts[typeIndex + 1] === 'host') {
    parts[typeIndex + 1] = 'srflx'
  }
  if (fingerprint.webrtc_udp_only === true) {
    parts[2] = 'udp'
  }

  const nextLine = parts.join(' ')
  return prefixed ? `a=${nextLine}` : nextLine
}

function sanitizeSessionDescription(runtime, description, fingerprint) {
  if (!description?.sdp) {
    return description
  }

  const candidateLimit = Math.max(1, Number(fingerprint.webrtc_candidate_limit) || 4)
  let candidates = 0
  const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '104.244.72.1'
  const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:4860:4860::8888'
  const sanitized = String(description.sdp)
    .split(/\r?\n/)
    .filter((line) => {
      if (!line.startsWith('a=candidate')) {
        return true
      }
      candidates += 1
      return candidates <= candidateLimit
    })
    .map((line) => {
      if (line.startsWith('a=candidate')) {
        return sanitizeCandidateLine(line, fingerprint)
      }
      if (line.startsWith('c=IN IP4')) {
        return `c=IN IP4 ${publicIpv4}`
      }
      if (line.startsWith('c=IN IP6')) {
        return `c=IN IP6 ${publicIpv6}`
      }
      return line
    })
    .join('\r\n')

  if (sanitized === description.sdp) {
    return description
  }

  if (typeof runtime.nativeRefs.RTCSessionDescription === 'function') {
    try {
      return new runtime.nativeRefs.RTCSessionDescription({ type: description.type, sdp: sanitized })
    } catch {
      // ignore
    }
  }

  return { type: description.type, sdp: sanitized }
}

function sanitizeIceCandidate(runtime, candidate, fingerprint) {
  if (!candidate || typeof candidate.candidate !== 'string') {
    return candidate
  }

  const sanitizedLine = sanitizeCandidateLine(candidate.candidate, fingerprint)
  if (!sanitizedLine || sanitizedLine === candidate.candidate) {
    return candidate
  }

  if (typeof runtime.nativeRefs.RTCIceCandidate === 'function') {
    try {
      return new runtime.nativeRefs.RTCIceCandidate({
        candidate: sanitizedLine,
        sdpMid: candidate.sdpMid || null,
        sdpMLineIndex: candidate.sdpMLineIndex,
      })
    } catch {
      // ignore
    }
  }

  return { ...candidate, candidate: sanitizedLine }
}

export function installWebRTCSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  const peerPrototype = runtime.nativeRefs.peerPrototype
  if (!peerPrototype || runtime.modules.webrtc) {
    return
  }

  const listenerMap = new WeakMap()

  function processIceCandidate(peer, event) {
    if (!event?.candidate) {
      return true
    }
    const sanitized = sanitizeIceCandidate(runtime, event.candidate, fingerprint)
    if (sanitized !== event.candidate) {
      try {
        event.candidate = sanitized
      } catch {
        try {
          Object.defineProperty(event, 'candidate', {
            value: sanitized,
            configurable: true,
          })
        } catch {
          // ignore
        }
      }
    }
    return true
  }

  if (runtime.nativeRefs.peerAddEventListener) {
    defineMethod(peerPrototype, 'addEventListener', markNativeCode(function addEventListener(type, listener, options) {
      if (type === 'icecandidate' && typeof listener === 'function') {
        let wrapped = listenerMap.get(listener)
        if (!wrapped) {
          wrapped = function icecandidate(event) {
            processIceCandidate(this, event)
            return listener.call(this, event)
          }
          listenerMap.set(listener, wrapped)
        }
        return runtime.nativeRefs.peerAddEventListener.call(this, type, wrapped, options)
      }
      return runtime.nativeRefs.peerAddEventListener.apply(this, arguments)
    }, 'addEventListener'))
  }

  if (runtime.nativeRefs.peerRemoveEventListener) {
    defineMethod(peerPrototype, 'removeEventListener', markNativeCode(function removeEventListener(type, listener, options) {
      if (type === 'icecandidate' && typeof listener === 'function') {
        return runtime.nativeRefs.peerRemoveEventListener.call(this, type, listenerMap.get(listener) || listener, options)
      }
      return runtime.nativeRefs.peerRemoveEventListener.apply(this, arguments)
    }, 'removeEventListener'))
  }

  const onIceDescriptor = Object.getOwnPropertyDescriptor(peerPrototype, 'onicecandidate')
  if (onIceDescriptor?.set) {
    Object.defineProperty(peerPrototype, 'onicecandidate', {
      configurable: true,
      enumerable: onIceDescriptor.enumerable,
      get: markNativeCode(function onicecandidate() {
        return originalOnIceCandidateHandlers.get(this) || null
      }, 'onicecandidate'),
      set: markNativeCode(function onicecandidate(handler) {
        originalOnIceCandidateHandlers.set(this, handler)
        if (typeof handler !== 'function') {
          wrappedOnIceCandidateHandlers.delete(this)
          return onIceDescriptor.set.call(this, handler)
        }
        const wrapped = (event) => {
          processIceCandidate(this, event)
          return handler.call(this, event)
        }
        wrappedOnIceCandidateHandlers.set(this, wrapped)
        return onIceDescriptor.set.call(this, wrapped)
      }, 'onicecandidate'),
    })
  }

  if (runtime.nativeRefs.peerSetLocalDescription) {
    defineMethod(peerPrototype, 'setLocalDescription', markNativeCode(function setLocalDescription(description) {
      const sanitized = sanitizeSessionDescription(runtime, description || this.localDescription, fingerprint)
      return runtime.nativeRefs.peerSetLocalDescription.call(this, sanitized)
    }, 'setLocalDescription'))
  }

  if (runtime.nativeRefs.peerCreateOffer) {
    defineMethod(peerPrototype, 'createOffer', markNativeCode(function createOffer(options) {
      return runtime.nativeRefs.peerCreateOffer.call(this, options)
        .then((description) => sanitizeSessionDescription(runtime, description, fingerprint))
    }, 'createOffer'))
  }

  if (runtime.nativeRefs.peerCreateAnswer) {
    defineMethod(peerPrototype, 'createAnswer', markNativeCode(function createAnswer(options) {
      return runtime.nativeRefs.peerCreateAnswer.call(this, options)
        .then((description) => sanitizeSessionDescription(runtime, description, fingerprint))
    }, 'createAnswer'))
  }

  markModule('webrtc')
}