import { getFingerprint } from '../core/config.js'
import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const wrappedPorts = new WeakSet()

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

function scrubAudioBuffer(payload, rng) {
  const applyNoise = (entry) => {
    if (!entry || typeof entry.length !== 'number') {
      return
    }
    for (let index = 0; index < entry.length; index += 1) {
      entry[index] += (rng() - 0.5) * 1e-4
    }
  }

  if (ArrayBuffer.isView(payload)) {
    applyNoise(payload)
    return
  }
  if (Array.isArray(payload)) {
    payload.forEach((entry) => applyNoise(entry))
    return
  }
  if (Array.isArray(payload?.channelData)) {
    payload.channelData.forEach((entry) => applyNoise(entry))
  }
}

function wrapWorkletPort(runtime, fingerprint, port, label) {
  if (!port || wrappedPorts.has(port)) {
    return port
  }

  wrappedPorts.add(port)
  const rng = createScopedRng(runtime, fingerprint, 'audio-worklet', label)

  if (typeof port.postMessage === 'function') {
    const nativePostMessage = port.postMessage.bind(port)
    defineMethod(port, 'postMessage', markNativeCode(function postMessage(message, transfer) {
      scrubAudioBuffer(message, rng)
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
        scrubAudioBuffer(event?.data, rng)
        return listener.call(this, event)
      }
      return nativeAddEventListener(type, wrapped, options)
    }, 'addEventListener'))
  }

  return port
}

export function installAudioSpoof() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  if (runtime.modules.audio) {
    return
  }

  if (runtime.nativeRefs.offlineStartRendering) {
    defineMethod(runtime.nativeRefs.offlineAudioPrototype, 'startRendering', markNativeCode(function startRendering() {
      return runtime.nativeRefs.offlineStartRendering.apply(this, arguments).then((buffer) => {
        const rng = createScopedRng(runtime, fingerprint, 'audio-buffer', `${buffer?.length || 0}`)
        try {
          for (let channel = 0; channel < (buffer?.numberOfChannels || 0); channel += 1) {
            scrubAudioBuffer(buffer.getChannelData(channel), rng)
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
      const rng = createScopedRng(runtime, fingerprint, 'audio-oscillator', oscillator.type || 'sine')
      defineMethod(oscillator, 'start', markNativeCode(function start(when) {
        try {
          if (oscillator.frequency && typeof oscillator.frequency.setValueAtTime === 'function') {
            const baseFrequency = oscillator.frequency.value || 440
            oscillator.frequency.setValueAtTime(baseFrequency + ((rng() - 0.5) * 0.6), when || 0)
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
    const analyserRng = new WeakMap()
    let analyserCounter = 0
    defineMethod(runtime.nativeRefs.analyserPrototype, 'getFloatFrequencyData', markNativeCode(function getFloatFrequencyData(array) {
      const result = runtime.nativeRefs.analyserGetFloatFrequencyData.call(this, array)
      let rng = analyserRng.get(this)
      if (!rng) {
        rng = createScopedRng(runtime, fingerprint, 'audio-analyser', `${analyserCounter}`)
        analyserCounter += 1
        analyserRng.set(this, rng)
      }
      scrubAudioBuffer(array, rng)
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
          return wrapWorkletPort(runtime, fingerprint, port, this?.constructor?.name || 'AudioWorkletNode')
        }, 'port'),
      })
    }
  }

  markModule('audio')
}