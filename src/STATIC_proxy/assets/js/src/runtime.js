/*
 * STATIC Runtime v5.0.0
 * Eligible network worker responses bootstrap selected realm-local surfaces.
 * Cached, pre-existing, blob/data workers and worklet processors remain gaps.
 * Frame fallback can run after child code and requires CSP-allowed compilation.
 */

import { finishRuntime, getRuntime, initRuntime } from './core/guard.js'
import { captureNativeRefs } from './core/native-refs.js'
import { installToStringProxy } from './core/toString.js'
import { captureNonce } from './core/nonce.js'
import { loadConfig } from './core/config.js'
import { initEntropy } from './core/entropy.js'
import { getPolicy, initPolicy } from './core/policy.js'

import { installNavigator } from './identity/navigator.js'
import { installFontMetrics } from './identity/fonts.js'
import { installPlugins } from './identity/plugins.js'
import { installScreen } from './identity/screen.js'
import { installPerformance } from './identity/performance.js'
import { installTimezone } from './identity/timezone.js'

import { installPermissions } from './capabilities/permissions.js'
import { installNotifications } from './capabilities/notifications.js'
import { installBattery } from './capabilities/battery.js'
import { installStorage } from './capabilities/storage.js'
import { installNetwork } from './capabilities/network.js'
import { installMediaCapabilities } from './capabilities/media-capabilities.js'
import { installAudioSpoof } from './spoofing/audio.js'
import { installCanvasSpoof } from './spoofing/canvas.js'
import { installEventTimingSpoof } from './spoofing/event-timing.js'
import { installGamepadSpoof } from './spoofing/gamepad.js'
import { installMediaDevicesSpoof } from './spoofing/media-devices.js'
import { installSpeechSpoof } from './spoofing/speech.js'
import { installWebGLSpoof } from './spoofing/webgl.js'
import { installWebRTCSpoof } from './spoofing/webrtc.js'

import { installAutomationEvasion } from './evasion/automation.js'
import { installGeolocationDenial } from './evasion/geolocation.js'
import { installBeaconBlackhole } from './privacy/beacon-blackhole.js'
import { installIframePropagation } from './contexts/iframe.js'

export function startRuntime(rawConfig, initializeChild) {
  'use strict'

  if (!initRuntime()) {
    return getRuntime().state
  }

  try {
    loadConfig(rawConfig)
    captureNativeRefs()
    captureNonce()
    initEntropy()
    initPolicy()
    installToStringProxy()

    const policy = getPolicy()
    getRuntime().coverage = Object.freeze({
      window: 'partial', sameOriginFrames: 'partial', srcdoc: 'partial',
      crossOriginFrames: 'unverified: own proxy response required',
      networkWorkers: 'unverified: own proxy response required; selected identity/capability/clock/metadata surfaces',
      blobDataWorkers: 'unsupported', preexistingWorkers: 'unsupported', audioWorklet: 'unsupported',
    })

    installNavigator()
    installScreen()

    if (policy.fontMetricsEnabled) {
      installFontMetrics()
    }

    if (policy.pluginEnabled) {
      installPlugins()
    }
    if (policy.performanceEnabled) {
      installPerformance()
    }
    if (policy.timezoneEnabled) {
      installTimezone()
    }

    installPermissions()
    installNotifications()
    installBattery()

    if (policy.storageEnabled) {
      installStorage()
    }
    if (policy.networkEnabled) {
      installNetwork()
    }
    if (policy.mediaCapabilitiesEnabled) {
      installMediaCapabilities()
    }

    if (policy.canvasEnabled) {
      installCanvasSpoof()
    }
    if (policy.webglEnabled) {
      installWebGLSpoof()
    }
    if (policy.audioEnabled) {
      installAudioSpoof()
    }
    if (policy.webrtcEnabled) {
      installWebRTCSpoof()
    }
    if (policy.mediaDevicesEnabled) {
      installMediaDevicesSpoof()
    }
    if (policy.gamepadEnabled) {
      installGamepadSpoof()
    }
    if (policy.speechEnabled) {
      installSpeechSpoof()
    }
    if (policy.eventTimingEnabled) {
      installEventTimingSpoof()
    }

    if (policy.automationEvasionEnabled) {
      installAutomationEvasion()
    }
    if (policy.geolocationEnabled) {
      installGeolocationDenial()
    }
    if (policy.privacyBlackholeEnabled) {
      installBeaconBlackhole()
    }
    if (policy.iframePropagationEnabled) {
      installIframePropagation(initializeChild)
    }
    const optional = {
      fontMetrics: policy.fontMetricsEnabled, plugins: policy.pluginEnabled,
      performance: policy.performanceEnabled, timezone: policy.timezoneEnabled,
      storage: policy.storageEnabled, network: policy.networkEnabled,
      mediaCapabilities: policy.mediaCapabilitiesEnabled, canvas: policy.canvasEnabled,
      webgl: policy.webglEnabled, audio: policy.audioEnabled, webrtc: policy.webrtcEnabled,
      mediaDevices: policy.mediaDevicesEnabled, gamepad: policy.gamepadEnabled,
      speech: policy.speechEnabled, eventTiming: policy.eventTimingEnabled,
      automation: policy.automationEvasionEnabled, geolocation: policy.geolocationEnabled,
      privacyBlackhole: policy.privacyBlackholeEnabled, iframePropagation: policy.iframePropagationEnabled,
    }
    for (const [name, enabled] of Object.entries(optional)) {
      if (!enabled) getRuntime().outcomes[name] = Object.freeze({ status: 'disabled' })
    }
    finishRuntime()
    return 'ready'
  } catch (error) {
    finishRuntime(error)
    console.error('[STATIC] runtime initialization failed:', error.message)
    return 'failed'
  }
}
