import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const GENERIC_LABELS = {
  audioinput: ['Default - Microphone', 'Communications - Microphone', 'Microphone'],
  audiooutput: ['Default - Speakers', 'Communications - Speakers', 'Speakers'],
  videoinput: ['Integrated Camera', 'USB Camera', 'Camera'],
}

const trackLabelState = new WeakMap()

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function deterministicId(runtime, prefix, key) {
  return `${prefix}-${runtime.entropy.hash(`${prefix}:${key}`).toString(16).padStart(8, '0')}`
}

function getProfileDevices(fingerprint) {
  return Array.isArray(fingerprint.media_devices) ? fingerprint.media_devices : []
}

function resolveProfileDevice(fingerprint, kind, index, perKindIndex) {
  if (!Array.isArray(fingerprint.media_devices)) {
    return null
  }

  const byKind = fingerprint.media_devices.filter((entry) => entry?.kind === kind)
  if (byKind[perKindIndex]) {
    return byKind[perKindIndex]
  }

  return fingerprint.media_devices.find((entry) => entry?.kind === kind) || fingerprint.media_devices[index] || null
}

function syntheticLabel(kind, index, profile) {
  if (profile?.label) {
    return profile.label
  }

  const options = GENERIC_LABELS[kind]
  if (Array.isArray(options) && options.length > 0) {
    return options[index % options.length]
  }

  return ''
}

function inferTargetCount(fingerprint, devices) {
  if (Number.isInteger(fingerprint.media_device_count) && fingerprint.media_device_count > 0) {
    return fingerprint.media_device_count
  }

  const profileDevices = getProfileDevices(fingerprint)
  if (profileDevices.length > 0) {
    return profileDevices.length
  }

  const kinds = new Set((Array.isArray(devices) ? devices : []).map((device) => device?.kind).filter(Boolean))
  if (kinds.size === 0) {
    return 3
  }

  return Math.min(3, Math.max(1, kinds.size))
}

function normalizeDeviceList(fingerprint, devices) {
  if (!Array.isArray(devices) || devices.length === 0) {
    return []
  }

  const targetCount = inferTargetCount(fingerprint, devices)
  const selected = []
  const seenKinds = new Set()

  for (const device of devices) {
    const kind = device?.kind || ''
    if (!seenKinds.has(kind)) {
      selected.push(device)
      seenKinds.add(kind)
    }
    if (selected.length >= targetCount) {
      return selected
    }
  }

  for (const device of devices) {
    if (!selected.includes(device)) {
      selected.push(device)
    }
    if (selected.length >= targetCount) {
      break
    }
  }

  return selected
}

function cloneMediaDevice(runtime, fingerprint, device, index, perKindIndex) {
  const source = device && typeof device === 'object' ? device : {}
  const profile = resolveProfileDevice(fingerprint, source.kind, index, perKindIndex) || {}
  const kind = source.kind || profile.kind || 'audioinput'
  const label = syntheticLabel(kind, perKindIndex, profile)
  const key = `${kind}:${profile.deviceId || profile.label || 'unknown'}:${index}:${perKindIndex}:${runtime.entropy.sessionId}`

  const cloned = {
    deviceId: deterministicId(runtime, 'device', key),
    groupId: deterministicId(runtime, 'group', key),
    kind,
    label,
  }

  for (const property of ['facingMode', 'vendorId', 'productId']) {
    if (Object.prototype.hasOwnProperty.call(profile, property)) {
      cloned[property] = profile[property]
    } else if (Object.prototype.hasOwnProperty.call(source, property)) {
      cloned[property] = source[property]
    }
  }

  return Object.freeze(cloned)
}

function syntheticTrackLabel(track, fingerprint) {
  const kind = track?.kind === 'video' ? 'videoinput' : 'audioinput'
  const profile = resolveProfileDevice(fingerprint, kind, 0, 0) || null
  return syntheticLabel(kind, 0, profile)
}

function patchTrackLabel(runtime, fingerprint, track) {
  if (!track || (typeof track !== 'object' && typeof track !== 'function')) {
    return
  }
  if (trackLabelState.has(track)) {
    return
  }

  const label = syntheticTrackLabel(track, fingerprint)
  const defineProperty = runtime.nativeRefs.defineProperty
  defineProperty(track, 'label', {
    get: markNativeCode(function label() {
      return label
    }, 'label'),
    configurable: true,
    enumerable: false,
  })
  trackLabelState.set(track, label)
}

function patchStreamTracks(runtime, fingerprint, stream) {
  if (!stream || typeof stream !== 'object') {
    return stream
  }

  const getTracks = runtime.nativeRefs.mediaStreamGetTracks
  if (typeof getTracks !== 'function') {
    return stream
  }

  try {
    const tracks = getTracks.call(stream)
    if (Array.isArray(tracks)) {
      for (const track of tracks) {
        patchTrackLabel(runtime, fingerprint, track)
      }
    }
  } catch {
    // ignore
  }

  return stream
}

export function installMediaDevicesSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  if (!runtime.nativeRefs.mediaDevicesPrototype || runtime.modules.mediaDevices) {
    return
  }

  if (runtime.nativeRefs.enumerateDevices) {
    defineMethod(runtime.nativeRefs.mediaDevicesPrototype, 'enumerateDevices', markNativeCode(function enumerateDevices() {
      return Promise.resolve(runtime.nativeRefs.enumerateDevices.apply(this, arguments))
        .then((devices) => {
          if (!Array.isArray(devices)) {
            return devices
          }

          const normalized = normalizeDeviceList(fingerprint, devices)
          const perKindCounts = new Map()
          return normalized.map((device, index) => {
            const kind = device?.kind || 'audioinput'
            const perKindIndex = perKindCounts.get(kind) || 0
            perKindCounts.set(kind, perKindIndex + 1)
            return cloneMediaDevice(runtime, fingerprint, device, index, perKindIndex)
          })
        })
    }, 'enumerateDevices'))
  }

  if (runtime.nativeRefs.getUserMedia) {
    defineMethod(runtime.nativeRefs.mediaDevicesPrototype, 'getUserMedia', markNativeCode(function getUserMedia() {
      return Promise.resolve(runtime.nativeRefs.getUserMedia.apply(this, arguments))
        .then((stream) => patchStreamTracks(runtime, fingerprint, stream))
    }, 'getUserMedia'))
  }

  markModule('mediaDevices')
}