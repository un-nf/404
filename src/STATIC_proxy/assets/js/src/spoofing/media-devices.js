import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter, replaceMethod, mapMethod } from '../core/descriptors.js'
import { markNativeLike } from '../core/toString.js'

export function installMediaDevicesSpoof() {
  const devices = navigator.mediaDevices
  if (!devices) { markModule('mediaDevices', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  // Opaque random aliases do not expose a reversible hash of a device ID. Maps
  // stay private and are used in both observation and selection directions.
  const aliases = { deviceId: new Map(), groupId: new Map() }
  const originals = { deviceId: new Map(), groupId: new Map() }
  const random = crypto.getRandomValues.bind(crypto)
  const alias = (key, value) => {
    if (!value || value === 'default' || value === 'communications') return value
    if (!aliases[key].has(value)) {
      const bytes = random(new Uint8Array(32))
      const id = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
      aliases[key].set(value, id); originals[key].set(id, value)
    }
    return aliases[key].get(value)
  }
  const unalias = (key, value) => originals[key].get(value) ?? value
  const translate = (key, value) => {
    if (typeof value === 'string') return unalias(key, value)
    if (Array.isArray(value)) return value.map((entry) => translate(key, entry))
    if (value && typeof value === 'object') return new Proxy({}, { get(_target, name) {
      const item = Reflect.get(value, name, value)
      return name === 'exact' || name === 'ideal' ? translate(key, item) : item
    } })
    return value
  }
  const constraints = (value) => value && typeof value === 'object' ? new Proxy({}, {
    get(_target, key) {
      const item = Reflect.get(value, key, value)
      if (key === 'deviceId' || key === 'groupId') return translate(key, item)
      if (key === 'audio' || key === 'video') return constraints(item)
      if (key === 'advanced' && Array.isArray(item)) return item.map(constraints)
      return item
    },
  }) : value
  for (const key of ['deviceId', 'groupId']) {
    replaceGetter(globalThis.MediaDeviceInfo?.prototype, key, (value) => alias(key, value))
  }
  const labels = { audioinput: 'Microphone', audiooutput: 'Speakers', videoinput: 'Camera' }
  replaceGetter(globalThis.MediaDeviceInfo?.prototype, 'label', (label, device) => {
    if (!label) return label
    const configured = fp.media_devices?.find((item) => item.kind === device.kind)
    return configured?.label || labels[device.kind] || label
  })
  replaceGetter(globalThis.MediaStreamTrack?.prototype, 'label', (label, track) => {
    if (!label) return label
    const kind = track.kind === 'video' ? 'videoinput' : 'audioinput'
    return fp.media_devices?.find((item) => item.kind === kind)?.label || labels[kind]
  })
  mapMethod(globalThis.MediaDeviceInfo?.prototype, 'toJSON', (result, device) =>
    ({ ...result, deviceId: device.deviceId, groupId: device.groupId, label: device.label }))
  mapMethod(devices, 'enumerateDevices', (promise) => promise.then((list) => {
    const counts = new Map()
    const selected = list.filter((device) => {
      const count = counts.get(device.kind) || 0
      counts.set(device.kind, count + 1)
      const configured = fp.media_devices?.filter((entry) => entry.kind === device.kind).length
      return count < (configured || (fp.media_devices_per_kind ?? 1))
    })
    return selected.slice(0, fp.media_device_count ?? selected.length)
  }))
  replaceMethod(devices, 'getUserMedia', (native, receiver, args) =>
    Reflect.apply(native, receiver, [constraints(args[0]), ...args.slice(1)]))
  const observations = (result) => {
      for (const property of ['deviceId', 'groupId']) {
        if (typeof result[property] === 'string') result[property] = alias(property, result[property])
        else if (Array.isArray(result[property])) result[property] = result[property].map((value) => alias(property, value))
        else if (result[property] && typeof result[property] === 'object') {
          for (const constraint of ['exact', 'ideal']) {
            const value = result[property][constraint]
            if (typeof value === 'string') result[property][constraint] = alias(property, value)
            else if (Array.isArray(value)) result[property][constraint] = value.map((item) => alias(property, item))
          }
        }
      }
      return result
  }
  for (const key of ['getSettings', 'getCapabilities', 'getConstraints']) {
    mapMethod(globalThis.MediaStreamTrack?.prototype, key, observations)
  }
  mapMethod(globalThis.InputDeviceInfo?.prototype, 'getCapabilities', observations)
  replaceMethod(globalThis.MediaStreamTrack?.prototype, 'applyConstraints', (native, receiver, args) =>
    Reflect.apply(native, receiver, args.length ? [constraints(args[0]), ...args.slice(1)] : args))
  const sink = globalThis.HTMLMediaElement?.prototype
  replaceGetter(sink, 'sinkId', (value) => alias('deviceId', value))
  replaceMethod(sink, 'setSinkId', (native, receiver, args) =>
    Reflect.apply(native, receiver, args.length ? [translate('deviceId', args[0]), ...args.slice(1)] : args))
  replaceMethod(devices, 'selectAudioOutput', (native, receiver, args) =>
    Reflect.apply(native, receiver, args.length ? [constraints(args[0]), ...args.slice(1)] : args))
  const AudioContext = globalThis.AudioContext
  if (typeof AudioContext === 'function') {
    const audio = AudioContext.prototype
    replaceGetter(audio, 'sinkId', (value) => typeof value === 'string' ? alias('deviceId', value) : value)
    replaceMethod(audio, 'setSinkId', (native, receiver, args) => Reflect.apply(native, receiver,
      args.length && typeof args[0] === 'string' ? [unalias('deviceId', args[0]), ...args.slice(1)] : args))
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'AudioContext')
    if (descriptor?.writable || descriptor?.configurable) {
      const wrapped = markNativeLike(new Proxy(AudioContext, { construct(native, args, newTarget) {
        const options = args[0]
        const converted = options && typeof options === 'object' ? new Proxy({}, { get(_target, key) {
          const value = Reflect.get(options, key, options)
          return key === 'sinkId' && typeof value === 'string' ? unalias('deviceId', value) : value
        } }) : options
        return Reflect.construct(native, args.length ? [converted, ...args.slice(1)] : args, newTarget)
      } }), AudioContext)
      Object.defineProperty(globalThis, 'AudioContext', { ...descriptor, value: wrapped })
      if (globalThis.webkitAudioContext === AudioContext) {
        const aliasDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'webkitAudioContext')
        if (aliasDescriptor?.writable || aliasDescriptor?.configurable) {
          Object.defineProperty(globalThis, 'webkitAudioContext', { ...aliasDescriptor, value: wrapped })
        }
      }
      const constructor = Object.getOwnPropertyDescriptor(audio, 'constructor')
      if (constructor?.writable || constructor?.configurable) {
        Object.defineProperty(audio, 'constructor', { ...constructor, value: wrapped })
      }
    }
  }
  markModule('mediaDevices', { status: 'partial', detail: 'native objects with bounded inventory, opaque IDs, translated selection and settings; permission gating retained' })
}
