import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const wrappedPorts = new WeakSet()

const DEFAULT_AUDIO_HARDWARE_PROFILES = {
  integrated: [
    {
      id: 'integrated_realtek_interactive',
      sample_rate: 48000,
      base_frames: 256,
      output_latency: 0.0215,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 0.99999955,
        bias: 1.15e-7,
        feedback: 1.6e-7,
        modulation: 2.2e-8,
        modulation_period: 384,
        step_offset: 6.5e-8,
        step_stride: 149,
      },
    },
    {
      id: 'integrated_conexant_playback',
      sample_rate: 48000,
      base_frames: 512,
      output_latency: 0.034,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 1.00000022,
        bias: -9.5e-8,
        feedback: 2.1e-7,
        modulation: 1.8e-8,
        modulation_period: 512,
        step_offset: -5.5e-8,
        step_stride: 173,
      },
    },
  ],
  usb: [
    {
      id: 'usb_headset_48k',
      sample_rate: 48000,
      base_frames: 256,
      output_latency: 0.041,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 0.9999999,
        bias: 7.8e-8,
        feedback: 2.9e-7,
        modulation: 2.5e-8,
        modulation_period: 441,
        step_offset: 7.2e-8,
        step_stride: 131,
      },
    },
    {
      id: 'usb_codec_44k1',
      sample_rate: 44100,
      base_frames: 256,
      output_latency: 0.049,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 1.00000008,
        bias: -8.1e-8,
        feedback: 2.4e-7,
        modulation: 2.0e-8,
        modulation_period: 367,
        step_offset: -4.2e-8,
        step_stride: 157,
      },
    },
  ],
  dock: [
    {
      id: 'dock_displaylink_48k',
      sample_rate: 48000,
      base_frames: 512,
      output_latency: 0.056,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 0.99999972,
        bias: 6.4e-8,
        feedback: 3.1e-7,
        modulation: 2.9e-8,
        modulation_period: 523,
        step_offset: 8.6e-8,
        step_stride: 181,
      },
    },
  ],
  bluetooth: [
    {
      id: 'bluetooth_a2dp_48k',
      sample_rate: 48000,
      base_frames: 512,
      output_latency: 0.118,
      channel_count: 2,
      max_channel_count: 2,
      number_of_inputs: 1,
      number_of_outputs: 0,
      render: {
        gain: 1.00000012,
        bias: -6.3e-8,
        feedback: 3.6e-7,
        modulation: 3.3e-8,
        modulation_period: 613,
        step_offset: -9.1e-8,
        step_stride: 199,
      },
    },
  ],
}

const AUDIO_HARDWARE_CLASS_PATTERNS = [
  { name: 'bluetooth', pattern: /(bluetooth|airpods|buds|headphones|a2dp)/i },
  { name: 'dock', pattern: /(dock|displaylink|thunderbolt)/i },
  { name: 'usb', pattern: /(usb|headset|jabra|poly|plantronics)/i },
  { name: 'integrated', pattern: /(realtek|conexant|speakers|microphone array|intel|dell)/i },
]

function defineGetter(target, name, getter, enumerable = false) {
  Object.defineProperty(target, name, {
    get: markNativeCode(getter, name),
    configurable: true,
    enumerable,
  })
}

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function createScopedRng(runtime, fingerprint, label, salt = 'static') {
  const seed = runtime.entropy.hash(`${label}:${fingerprint.audio_hash || 'static'}:${salt}:${runtime.entropy.sessionId}`)
  return runtime.entropy.rng(seed)
}

function numericField(value, fallback) {
  const resolved = Number(value)
  return Number.isFinite(resolved) ? resolved : fallback
}

function getAudioDeviceLabels(fingerprint) {
  if (!Array.isArray(fingerprint.media_devices)) {
    return []
  }

  return fingerprint.media_devices
    .map((entry) => String(entry?.label || '').trim())
    .filter(Boolean)
}

function classifyAudioHardware(fingerprint, audioContext) {
  const explicitClass = String(audioContext.hardware_class || '').trim().toLowerCase()
  if (explicitClass && DEFAULT_AUDIO_HARDWARE_PROFILES[explicitClass]) {
    return explicitClass
  }

  const labels = getAudioDeviceLabels(fingerprint)
  for (const label of labels) {
    for (const candidate of AUDIO_HARDWARE_CLASS_PATTERNS) {
      if (candidate.pattern.test(label)) {
        return candidate.name
      }
    }
  }

  return 'integrated'
}

function chooseWeightedProfile(runtime, fingerprint, profiles, label) {
  if (!Array.isArray(profiles) || profiles.length === 0) {
    return null
  }

  const totalWeight = profiles.reduce((sum, profile) => sum + Math.max(0, numericField(profile?.weight, 1)), 0)
  if (totalWeight <= 0) {
    return profiles[0]
  }

  const rng = createScopedRng(runtime, fingerprint, 'audio-hardware', label)
  let cursor = rng() * totalWeight

  for (const profile of profiles) {
    const weight = Math.max(0, numericField(profile?.weight, 1))
    if (cursor <= weight) {
      return profile
    }
    cursor -= weight
  }

  return profiles[profiles.length - 1]
}

function resolveAudioHardwareProfile(runtime, fingerprint) {
  const audioContext = fingerprint.audio_context || {}
  const configuredProfiles = Array.isArray(audioContext.hardware_profiles)
    ? audioContext.hardware_profiles
    : null
  if (configuredProfiles?.length) {
    return chooseWeightedProfile(runtime, fingerprint, configuredProfiles, 'configured')
  }

  const deviceClass = classifyAudioHardware(fingerprint, audioContext)
  const defaults = DEFAULT_AUDIO_HARDWARE_PROFILES[deviceClass] || DEFAULT_AUDIO_HARDWARE_PROFILES.integrated
  return chooseWeightedProfile(runtime, fingerprint, defaults, deviceClass)
}

function buildRenderModel(runtime, fingerprint, profile) {
  const configured = profile?.render || {}
  const rng = createScopedRng(runtime, fingerprint, 'audio-render', profile?.id || 'default')
  const withDrift = (base, spread) => base + ((rng() - 0.5) * spread)

  return {
    gain: withDrift(numericField(configured.gain, 1), 7.5e-7),
    bias: withDrift(numericField(configured.bias, 0), 4.0e-8),
    feedback: withDrift(numericField(configured.feedback, 2.2e-7), 7.5e-8),
    modulation: withDrift(numericField(configured.modulation, 2.0e-8), 7.5e-9),
    modulationPeriod: Math.max(97, Math.round(withDrift(numericField(configured.modulation_period, 431), 41))),
    stepOffset: withDrift(numericField(configured.step_offset, 5.0e-8), 2.5e-8),
    stepStride: Math.max(53, Math.round(withDrift(numericField(configured.step_stride, 149), 17))),
  }
}

function resolveAudioPersona(runtime, fingerprint) {
  const audioContext = fingerprint.audio_context || {}
  const hardwareProfile = resolveAudioHardwareProfile(runtime, fingerprint) || {}
  const sampleRate = numericField(hardwareProfile.sample_rate, numericField(audioContext.sample_rate, 48000))
  const baseFrames = Math.max(128, Math.round(numericField(hardwareProfile.base_frames, 256)))
  const configuredBaseLatency = numericField(audioContext.base_latency, Number.NaN)
  const configuredOutputLatency = numericField(audioContext.output_latency, Number.NaN)
  const baseLatency = Number.isFinite(configuredBaseLatency) && configuredBaseLatency >= 0
    ? configuredBaseLatency
    : numericField(hardwareProfile.base_latency, baseFrames / sampleRate)
  const outputLatency = Number.isFinite(configuredOutputLatency) && configuredOutputLatency >= 0
    ? configuredOutputLatency
    : Math.max(baseLatency, numericField(hardwareProfile.output_latency, baseLatency * 2.2))

  return {
    id: String(hardwareProfile.id || 'default'),
    hardwareClass: classifyAudioHardware(fingerprint, audioContext),
    sampleRate,
    baseLatency,
    outputLatency,
    channelCount: Math.max(1, Math.round(numericField(hardwareProfile.channel_count, numericField(audioContext.channel_count, 2)))),
    maxChannelCount: Math.max(1, Math.round(numericField(hardwareProfile.max_channel_count, numericField(audioContext.max_channel_count, 2)))),
    numberOfInputs: Math.max(0, Math.round(numericField(hardwareProfile.number_of_inputs, numericField(audioContext.number_of_inputs, 1)))),
    numberOfOutputs: Math.max(0, Math.round(numericField(hardwareProfile.number_of_outputs, numericField(audioContext.number_of_outputs, 0)))),
    renderModel: buildRenderModel(runtime, fingerprint, hardwareProfile),
  }
}

function transformAudioEntry(entry, renderModel, clampToUnitRange = false) {
  if (!entry || typeof entry.length !== 'number') {
    return
  }

  let previous = 0
  for (let index = 0; index < entry.length; index += 1) {
    const original = entry[index]
    let next = (original * renderModel.gain) + renderModel.bias + (previous * renderModel.feedback)
    next += Math.sin(index / renderModel.modulationPeriod) * renderModel.modulation
    if (index % renderModel.stepStride === 0) {
      next += renderModel.stepOffset
    }
    previous = original
    if (clampToUnitRange) {
      next = Math.max(-1, Math.min(1, next))
    }
    entry[index] = Math.fround(next)
  }
}

function applyAudioSignature(payload, renderModel, clampToUnitRange = false) {
  const apply = (entry) => transformAudioEntry(entry, renderModel, clampToUnitRange)

  if (ArrayBuffer.isView(payload)) {
    apply(payload)
    return
  }
  if (Array.isArray(payload)) {
    payload.forEach((entry) => apply(entry))
    return
  }
  if (Array.isArray(payload?.channelData)) {
    payload.channelData.forEach((entry) => apply(entry))
  }
}

function wrapWorkletPort(runtime, fingerprint, persona, port, label) {
  if (!port || wrappedPorts.has(port)) {
    return port
  }

  wrappedPorts.add(port)
  const renderModel = buildRenderModel(runtime, fingerprint, {
    id: `${persona.id}:${label}`,
    render: persona.renderModel,
  })

  if (typeof port.postMessage === 'function') {
    const nativePostMessage = port.postMessage.bind(port)
    defineMethod(port, 'postMessage', markNativeCode(function postMessage(message, transfer) {
      applyAudioSignature(message, renderModel)
      return nativePostMessage(message, transfer)
    }, 'postMessage'))
  }

  if (typeof port.addEventListener === 'function') {
    const nativeAddEventListener = port.addEventListener.bind(port)
    defineMethod(port, 'addEventListener', markNativeCode(function addEventListener(type, listener, options) {
      if (type !== 'message' || typeof listener !== 'function') {
        return nativeAddEventListener(type, listener, options)
      }
      const wrapped = function message(event) {
        applyAudioSignature(event?.data, renderModel)
        return listener.call(this, event)
      }
      return nativeAddEventListener(type, wrapped, options)
    }, 'addEventListener'))
  }

  return port
}

function installAudioContextGetters(runtime, fingerprint, persona) {
  const audioPrototypes = new Set([
    runtime.nativeRefs.baseAudioPrototype,
    window.AudioContext?.prototype || null,
    window.webkitAudioContext?.prototype || null,
    window.BaseAudioContext?.prototype || null,
  ].filter(Boolean))

  if (audioPrototypes.size === 0) {
    return
  }

  for (const prototype of audioPrototypes) {
    const sampleRateDescriptor = Object.getOwnPropertyDescriptor(prototype, 'sampleRate')
    const baseLatencyDescriptor = Object.getOwnPropertyDescriptor(prototype, 'baseLatency')
    const outputLatencyDescriptor = Object.getOwnPropertyDescriptor(prototype, 'outputLatency')

    defineGetter(prototype, 'sampleRate', function sampleRateGetter() {
      return persona.sampleRate
    }, sampleRateDescriptor?.enumerable ?? false)

    defineGetter(prototype, 'baseLatency', function baseLatencyGetter() {
      return persona.baseLatency
    }, baseLatencyDescriptor?.enumerable ?? false)

    if (outputLatencyDescriptor || 'outputLatency' in prototype) {
      defineGetter(prototype, 'outputLatency', function outputLatencyGetter() {
        return persona.outputLatency
      }, outputLatencyDescriptor?.enumerable ?? false)
    }
  }
}

function installAudioDestinationGetters(runtime, persona) {
  const prototype = runtime.nativeRefs.audioDestinationPrototype
  if (!prototype) {
    return
  }

  const channelCountDescriptor = Object.getOwnPropertyDescriptor(prototype, 'channelCount')
  const maxChannelCountDescriptor = Object.getOwnPropertyDescriptor(prototype, 'maxChannelCount')
  const numberOfInputsDescriptor = Object.getOwnPropertyDescriptor(prototype, 'numberOfInputs')
  const numberOfOutputsDescriptor = Object.getOwnPropertyDescriptor(prototype, 'numberOfOutputs')

  defineGetter(prototype, 'channelCount', function channelCountGetter() {
    return persona.channelCount
  }, channelCountDescriptor?.enumerable ?? false)

  defineGetter(prototype, 'maxChannelCount', function maxChannelCountGetter() {
    return persona.maxChannelCount
  }, maxChannelCountDescriptor?.enumerable ?? false)

  defineGetter(prototype, 'numberOfInputs', function numberOfInputsGetter() {
    return persona.numberOfInputs
  }, numberOfInputsDescriptor?.enumerable ?? false)

  defineGetter(prototype, 'numberOfOutputs', function numberOfOutputsGetter() {
    return persona.numberOfOutputs
  }, numberOfOutputsDescriptor?.enumerable ?? false)
}

export function installAudioSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  if (runtime.modules.audio) {
    return
  }

  const persona = resolveAudioPersona(runtime, fingerprint)

  if (runtime.nativeRefs.offlineStartRendering) {
    defineMethod(runtime.nativeRefs.offlineAudioPrototype, 'startRendering', markNativeCode(function startRendering() {
      return runtime.nativeRefs.offlineStartRendering.apply(this, arguments).then((buffer) => {
        try {
          for (let channel = 0; channel < (buffer?.numberOfChannels || 0); channel += 1) {
            applyAudioSignature(buffer.getChannelData(channel), persona.renderModel, true)
          }
        } catch {
          // ignore
        }
        return buffer
      })
    }, 'startRendering'))
  }

  if (runtime.nativeRefs.baseCreateOscillator) {
    defineMethod(runtime.nativeRefs.baseAudioPrototype, 'createOscillator', markNativeCode(function createOscillator() {
      const oscillator = runtime.nativeRefs.baseCreateOscillator.apply(this, arguments)
      if (!oscillator || typeof oscillator.start !== 'function') {
        return oscillator
      }
      const nativeStart = oscillator.start.bind(oscillator)
      defineMethod(oscillator, 'start', markNativeCode(function start(when) {
        try {
          if (oscillator.frequency && typeof oscillator.frequency.setValueAtTime === 'function') {
            const baseFrequency = oscillator.frequency.value || 440
            const drift = (persona.renderModel.modulation * 1.2e6) + (persona.renderModel.feedback * 8.0e5)
            oscillator.frequency.setValueAtTime(baseFrequency + drift, when || 0)
          }
        } catch {
          // ignore
        }
        return nativeStart.apply(this, arguments)
      }, 'start'))
      return oscillator
    }, 'createOscillator'))
  }

  if (runtime.nativeRefs.analyserGetFloatFrequencyData) {
    const analyserModel = new WeakMap()
    let analyserCounter = 0
    defineMethod(runtime.nativeRefs.analyserPrototype, 'getFloatFrequencyData', markNativeCode(function getFloatFrequencyData(array) {
      const result = runtime.nativeRefs.analyserGetFloatFrequencyData.call(this, array)
      let renderModel = analyserModel.get(this)
      if (!renderModel) {
        renderModel = buildRenderModel(runtime, fingerprint, {
          id: `${persona.id}:analyser:${analyserCounter}`,
          render: persona.renderModel,
        })
        analyserCounter += 1
        analyserModel.set(this, renderModel)
      }
      applyAudioSignature(array, renderModel)
      return result
    }, 'getFloatFrequencyData'))
  }

  if (runtime.nativeRefs.audioWorkletPrototype) {
    const portDescriptor = Object.getOwnPropertyDescriptor(runtime.nativeRefs.audioWorkletPrototype, 'port')
    if (portDescriptor?.get) {
      Object.defineProperty(runtime.nativeRefs.audioWorkletPrototype, 'port', {
        configurable: true,
        enumerable: portDescriptor.enumerable,
        get: markNativeCode(function port() {
          const port = portDescriptor.get.call(this)
          return wrapWorkletPort(runtime, fingerprint, persona, port, this?.constructor?.name || 'AudioWorkletNode')
        }, 'port'),
      })
    }
  }

  installAudioContextGetters(runtime, fingerprint, persona)
  installAudioDestinationGetters(runtime, persona)

  markModule('audio')
}