import { findDescriptor, replaceGetter, replaceMethod, mapMethod } from '../core/descriptors.js'
import { definePatch, transaction } from '../core/patches.js'
import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode, markNativeLike } from '../core/toString.js'

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

export function sanitizeCandidateLine(line, fingerprint) {
  if (typeof line !== 'string') {
    return line
  }

  const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '192.0.2.1'
  const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:db8::1'
  const trimmed = line.trim()
  const prefixed = trimmed.startsWith('a=')
  const payload = prefixed ? trimmed.slice(2) : trimmed
  const parts = payload.split(/\s+/)
  if (parts.length < 8) {
    return trimmed
  }

  const ipIndex = 4
  parts[ipIndex] = parts[ipIndex].includes(':') ? publicIpv6 : publicIpv4
  for(let index=8;index<parts.length-1;index++)if(parts[index]==='raddr')parts[index+1]=parts[index+1].includes(':')?publicIpv6:publicIpv4

  const nextLine = parts.join(' ')
  return prefixed ? `a=${nextLine}` : nextLine
}

function sanitizeSessionDescription(runtime, description, fingerprint) {
  if (!description?.sdp) {
    return description
  }

  const candidateLimit = Math.max(1, Number(fingerprint.webrtc_candidate_limit) || 4)
  let candidates = 0
  const publicIpv4 = fingerprint.webrtc_ip || fingerprint.ip_address || '192.0.2.1'
  const publicIpv6 = fingerprint.webrtc_ipv6 || '2001:db8::1'
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
        usernameFragment: candidate.usernameFragment,
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
  if(fingerprint.webrtc_transport_policy==='relay-only') {
    const enforce=config=>config==null?{iceTransportPolicy:'relay'}:new Proxy({}, {get(_target,key){
      const value=Reflect.get(config,key,config)
      if(key==='iceTransportPolicy') {
        if(value!==undefined&&!['all','relay'].includes(`${value}`))throw new TypeError('Invalid iceTransportPolicy')
        return 'relay'
      }
      return value
    }})
    const Native=runtime.nativeRefs.RTCPeerConnection
    const Wrapped=markNativeLike(new Proxy(Native,{construct(native,args,newTarget){
      const config=args[0]
      if(config!=null&&!['object','function'].includes(typeof config))return Reflect.construct(native,args,newTarget)
      return Reflect.construct(native,[enforce(config),...args.slice(1)],newTarget)
    }}),Native)
    for(const name of ['RTCPeerConnection','webkitRTCPeerConnection'])if(globalThis[name]===Native)definePatch(globalThis,name,{...Object.getOwnPropertyDescriptor(globalThis,name),value:Wrapped})
    definePatch(proto,'constructor',{...Object.getOwnPropertyDescriptor(proto,'constructor'),value:Wrapped})
    replaceMethod(proto,'setConfiguration',(native,receiver,args)=>{
      if(!args.length||args[0]!=null&&!['object','function'].includes(typeof args[0]))return Reflect.apply(native,receiver,args)
      return Reflect.apply(native,receiver,[enforce(args[0]),...args.slice(1)])
    })
  }
  const descriptions=new Map(),candidates=new Map(),candidateObjects=new WeakMap(),descriptionObjects=new WeakMap()
  const reports=new WeakSet(),values=new WeakMap(),iterators=new WeakMap(),reportPrototypes=new WeakSet(),iteratorPrototypes=new WeakSet()
  const maskStats=value=>{
    if(!value||typeof value!=='object')return value
    if(!values.has(value)) {
      const descriptors=Object.getOwnPropertyDescriptors(value)
      for(const key of ['address','ip','ipAddress','relatedAddress']) {
        const field=descriptors[key]
        if(typeof field?.value==='string'&&field.value)field.value=field.value.includes(':')?(fingerprint.webrtc_ipv6||'2001:db8::1'):(fingerprint.webrtc_ip||fingerprint.ip_address||'192.0.2.1')
      }
      values.set(value,Object.create(Object.getPrototypeOf(value),descriptors))
    }
    return values.get(value)
  }
  function wrapIterator(iterator,mode) {
    iterators.set(iterator,mode)
    const prototype=Object.getPrototypeOf(iterator)
    if(!iteratorPrototypes.has(prototype)) {
      if(!mapMethod(prototype,'next',(step,receiver)=>{
        const kind=iterators.get(receiver)
        if(kind&&!step.done)step.value=kind==='entries'?[step.value[0],maskStats(step.value[1])]:maskStats(step.value)
        return step
      }))throw new DOMException('Stats iterator masking unavailable','NotSupportedError')
      iteratorPrototypes.add(prototype)
    }
    return iterator
  }
  function shieldReportPrototype(prototype) {
    if(!reportPrototypes.has(prototype)) {
      transaction(()=>{
      const symbol=findDescriptor(prototype,Symbol.iterator),entry=findDescriptor(prototype,'entries')
      if(!mapMethod(prototype,'get',(value,receiver)=>reports.has(receiver)?maskStats(value):value))throw new DOMException('Stats masking unavailable','NotSupportedError')
      for(const kind of ['entries','values'])if(!mapMethod(prototype,kind,(iterator,receiver)=>reports.has(receiver)?wrapIterator(iterator,kind):iterator))throw new DOMException('Stats iteration masking unavailable','NotSupportedError')
      if(symbol?.descriptor.value===entry?.descriptor.value)definePatch(symbol.owner,Symbol.iterator,{...symbol.descriptor,value:findDescriptor(prototype,'entries').descriptor.value})
      else if(!mapMethod(prototype,Symbol.iterator,(iterator,receiver)=>reports.has(receiver)?wrapIterator(iterator,'entries'):iterator))throw new DOMException('Stats iteration masking unavailable','NotSupportedError')
      if(!replaceMethod(prototype,'forEach',(native,receiver,args)=>{
        if(!reports.has(receiver)||typeof args[0]!=='function')return Reflect.apply(native,receiver,args)
        return Reflect.apply(native,receiver,[(value,key,collection)=>Reflect.apply(args[0],args[1],[maskStats(value),key,collection])])
      }))throw new DOMException('Stats callback masking unavailable','NotSupportedError')
      })
      reportPrototypes.add(prototype)
    }
  }
  shieldReportPrototype(Map.prototype)
  if(globalThis.RTCStatsReport?.prototype)shieldReportPrototype(RTCStatsReport.prototype)
  wrapIterator(new Map().entries(),'entries')
  for(const target of [proto,globalThis.RTCRtpSender?.prototype,globalThis.RTCRtpReceiver?.prototype])if(target)mapMethod(target,'getStats',promise=>promise.then(report=>{
    shieldReportPrototype(Object.getPrototypeOf(report));reports.add(report);return report
  }))
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
  markModule('webrtc',{status:'partial',detail:'public/private/related candidate and stats address observations masked; native transport unchanged; same-realm alias reversal only; remote routing, stats IDs/ports/performance and clean-realm recovery remain incomplete'})
}
