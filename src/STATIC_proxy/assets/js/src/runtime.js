/*
 * STATIC Runtime v5.0.0 — Known Limitations
 *
 * 1. Worker and SharedWorker construction is intercepted through constructor
 *    wrapping, but service workers and pre-existing workers remain outside
 *    this bundle's reach and can still expose host-native values.
 *
 * 2. The high-entropy spoofing modules are being ported separately from
 *    the identity and capability baseline. This bundle currently focuses
 *    on prototype-correct identity ownership and compatibility-sensitive
 *    surfaces first.
 */

import { initRuntime } from './core/guard.js'
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

;(function staticRuntime() {
  'use strict'

  if (!initRuntime()) {
    return
  }

  captureNativeRefs()
  installToStringProxy()
  captureNonce()
  loadConfig()
  initEntropy()
  initPolicy()

  const policy = getPolicy()

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
    installIframePropagation()
  }
})()