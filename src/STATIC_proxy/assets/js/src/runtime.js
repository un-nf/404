import { installModule } from './core/installer.js'
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
    const runtime = getRuntime()
    if (!runtime.config?.ready) loadConfig(rawConfig)
    if (!runtime.nativeRefs.functionToString) captureNativeRefs()
    if (!runtime.nonceCaptured) { captureNonce(); runtime.nonceCaptured = true }
    if (!runtime.entropy) initEntropy()
    if (!runtime.policy) initPolicy()
    installModule('toString', true, installToStringProxy)
    if (runtime.outcomes.toString.status === 'failed') { finishRuntime(); return runtime.state }

    const policy = getPolicy()
    getRuntime().outcomes.configuration = Object.freeze({ status:getRuntime().config.contract.unsupported.length?'partial':'installed',
      unsupported:getRuntime().config.contract.unsupported })
    getRuntime().coverage = Object.freeze({
      window: 'partial', sameOriginFrames: 'partial', srcdoc: 'partial',
      crossOriginFrames: 'unverified: own proxy response required',
      networkWorkers: 'unverified: own proxy response required; selected identity/capability/clock/metadata surfaces',
      blobDataWorkers: 'unsupported', preexistingWorkers: 'unsupported', audioWorklet: 'unsupported',
    })

    const modules = [
      ['navigator', true, installNavigator], ['screen', true, installScreen],
      ['fontMetrics', policy.fontMetricsEnabled, installFontMetrics], ['plugins', policy.pluginEnabled, installPlugins],
      ['performance', policy.performanceEnabled, installPerformance], ['timezone', policy.timezoneEnabled, installTimezone],
      ['permissions', policy.permissionsEnabled, installPermissions], ['notifications', policy.notificationsEnabled, installNotifications],
      ['battery', policy.batteryEnabled, installBattery], ['storage', policy.storageEnabled, installStorage],
      ['network', policy.networkEnabled, installNetwork], ['mediaCapabilities', policy.mediaCapabilitiesEnabled, installMediaCapabilities],
      ['canvas', policy.canvasEnabled, installCanvasSpoof], ['webgl', policy.webglEnabled, installWebGLSpoof],
      ['audio', policy.audioEnabled, installAudioSpoof], ['webrtc', policy.webrtcEnabled, installWebRTCSpoof],
      ['mediaDevices', policy.mediaDevicesEnabled, installMediaDevicesSpoof], ['gamepad', policy.gamepadEnabled, installGamepadSpoof],
      ['speech', policy.speechEnabled, installSpeechSpoof], ['eventTiming', policy.eventTimingEnabled, installEventTimingSpoof],
      ['automation', policy.automationEvasionEnabled, installAutomationEvasion], ['geolocation', policy.geolocationEnabled, installGeolocationDenial],
      ['beaconBlackhole', policy.privacyBlackholeEnabled, installBeaconBlackhole],
      ['iframePropagation', policy.iframePropagationEnabled, () => installIframePropagation(initializeChild)],
    ]
    for (const [name, enabled, installer] of modules) installModule(name, enabled, installer)
    finishRuntime()
    return getRuntime().state
  } catch (error) {
    finishRuntime(error)
    console.error('[STATIC] runtime initialization failed:', error.message)
    return 'failed'
  }
}
