import { replaceGetter, replaceMethod, mapMethod } from '../core/descriptors.js'
import { definePatch } from '../core/patches.js'
import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const PRIVATE_IPV4 = /^(0\.|10\.|127\.|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)/
const PRIVATE_IPV6 = /^(::1|fc00:|fd00:|fe80:)/i
const originalOnIceCandidateHandlers = new WeakMap()
const wrappedOnIceCandidateHandlers = new WeakMap()

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  definePatch(target, name, {
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

  return candidate
}

export function installWebRTCSpoof() {
  const runtime=getRuntime(),fingerprint=getFingerprint(),proto=runtime.nativeRefs.peerPrototype
  if(!proto){markModule('webrtc',{status:'unavailable'});return}
  const descriptions=new Map(),candidates=new Map(),candidateObjects=new WeakMap(),descriptionObjects=new WeakMap()
  function maskDescription(value){
    if(!value||typeof value.sdp!=='string')return value
    const masked=sanitizeSessionDescription(runtime,value,fingerprint).sdp
    descriptions.set(masked,value.sdp)
    return {...value,type:value.type,sdp:masked}
  }
  replaceGetter(globalThis.RTCPeerConnectionIceEvent?.prototype,'candidate',candidate=>{
    if(!candidate)return candidate
    if(!candidateObjects.has(candidate)){
      const masked=sanitizeIceCandidate(runtime,candidate,fingerprint)
      if(masked.candidate!==candidate.candidate)candidates.set(masked.candidate,candidate.candidate)
      candidateObjects.set(candidate,masked)
    }
    return candidateObjects.get(candidate)
  })
  for(const name of ['createOffer','createAnswer'])mapMethod(proto,name,promise=>promise.then(maskDescription))
  for(const name of ['localDescription','remoteDescription','currentLocalDescription','pendingLocalDescription','currentRemoteDescription','pendingRemoteDescription']) {
    replaceGetter(proto,name,value=>{
      if(!value)return value
      if(!descriptionObjects.has(value)){
        const masked=maskDescription(value)
        descriptionObjects.set(value,typeof runtime.nativeRefs.RTCSessionDescription==='function'?new runtime.nativeRefs.RTCSessionDescription(masked):value)
      }
      return descriptionObjects.get(value)
    })
  }
  for(const [name,key,mapping]of [['setLocalDescription','sdp',descriptions],['setRemoteDescription','sdp',descriptions],['addIceCandidate','candidate',candidates]]) {
    replaceMethod(proto,name,(native,receiver,args)=>{
      const input=args[0]
      const translated=input&&typeof input==='object'?new Proxy({}, {get(_target,property){
        const value=Reflect.get(input,property,input)
        return property===key&&typeof value==='string'?mapping.get(value)??value:value
      }}):input
      return Reflect.apply(native,receiver,args.length?[translated,...args.slice(1)]:args)
    })
  }
  markModule('webrtc',{status:'partial',detail:'native event/handler contracts, all candidate listeners, bidirectional same-realm SDP/candidate mappings; remote wire endpoints/getStats and relay policy remain architectural work'})
}
