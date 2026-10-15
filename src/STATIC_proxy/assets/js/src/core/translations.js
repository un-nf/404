import { MapIntrinsic as Map, WeakMapIntrinsic as WeakMap } from './primordials.js'

// Owner- and generation-scoped reversal. Closed/expired generations never
// silently borrow another owner's original. Limits fail before exposure.
export function createTranslationStore(maxEntries = 128, maxBytes = 1048576) {
  let owners = new WeakMap(),ownership=new WeakMap(),disposed=false
  let retainedEntries = 0, retainedBytes = 0
  function state(owner) {
    if(disposed)throw new DOMException('Translation store disposed','AbortError')
    let value = owners.get(owner)
    if (!value) { value = { token:{},generation: 0, closed: false, strings: new Map(), objects: new WeakMap(), bytes: 0 }; owners.set(owner, value) }
    return value
  }
  function reset(owner, close = false) {
    const value = state(owner)
    retainedEntries -= value.strings.size; retainedBytes -= value.bytes
    value.strings.clear(); value.objects=new WeakMap(); value.bytes = 0
    value.generation++; value.closed = close
  }
  function record(owner, generation, object, type, masked, original) {
    const value = state(owner)
    if (value.closed || generation !== value.generation) throw new DOMException('Translation generation expired', 'AbortError')
    const key = type + '\u0000' + masked, prior = value.strings.get(key)
    if (prior && prior.original !== original) throw new DOMException('Ambiguous serialized translation', 'InvalidAccessError')
    if (!prior) {
      const bytes = 2 * (key.length + original.length)
      if (value.strings.size >= maxEntries || value.bytes + bytes > maxBytes)
        throw new DOMException('Translation budget exhausted; restart negotiation', 'QuotaExceededError')
      value.strings.set(key, { original }); value.bytes += bytes
      retainedEntries++; retainedBytes += bytes
    }
    if (object){value.objects.set(object, { type, masked, original, generation });ownership.set(object,{token:value.token,generation});}
    return object
  }
  function reverse(owner, object, type, masked) {
    const value = state(owner)
    if (value.closed) throw new DOMException('Connection closed', 'InvalidStateError')
    const known=object&&ownership.get(object);
    if(known&&known.token!==value.token)throw new DOMException('Description belongs to another connection','InvalidAccessError');
    if(known&&known.generation!==value.generation)throw new DOMException('Translation generation expired','InvalidStateError');
    const direct = object && value.objects.get(object)
    if(direct&&direct.generation!==value.generation)throw new DOMException('Translation generation expired','InvalidStateError')
    if (direct && direct.generation === value.generation && direct.type === type && direct.masked === masked) return direct.original
    const stored=value.strings.get(type + '\u0000' + masked);
    if(!stored&&value.generation>0)throw new DOMException('Unrecognized local description after generation expiry','InvalidStateError');
    return stored?.original ?? masked
  }
  return { generation: owner => state(owner).generation, record, reverse, reset,
    dispose:()=>{disposed=true;owners=new WeakMap();ownership=new WeakMap();retainedEntries=0;retainedBytes=0;},
    counters: () => ({ entries: retainedEntries, bytes: retainedBytes }) }
}
