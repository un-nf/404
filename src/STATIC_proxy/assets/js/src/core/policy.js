import { getRuntime } from './guard.js'
import { getFingerprint } from './config.js'

const STABILITY_HOSTS = [
  'google.com',
  'youtube.com',
  'youtube-nocookie.com',
  'ytimg.com',
  'googlevideo.com',
  'gstatic.com',
  'discord.com',
  'discordapp.com',
  'discord.gg',
  'recaptcha.net',
  'challenges.cloudflare.com',
]

function hostMatches(host, suffixes) {
  return suffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))
}

export function initPolicy() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  const host = (() => {
    try {
      return location.hostname
    } catch {
      return ''
    }
  })()
  const stabilityMode = hostMatches(host, STABILITY_HOSTS)

  runtime.policy = {
    host,
    stabilityMode,
    timezoneEnabled: fingerprint.enable_timezone_spoof !== false,
    performanceEnabled: fingerprint.enable_performance_spoof !== false,
    fontMetricsEnabled: fingerprint.enable_font_metric_spoof !== false,
    pluginEnabled: fingerprint.enable_plugin_spoof !== false,
    storageEnabled: fingerprint.enable_storage_spoof !== false,
    networkEnabled: fingerprint.enable_network_spoof !== false,
    mediaCapabilitiesEnabled: true,
    canvasEnabled: fingerprint.enable_canvas_spoof !== false,
    webglEnabled: fingerprint.enable_webgl_spoof !== false,
    audioEnabled: !stabilityMode && fingerprint.enable_audio_spoof !== false,
    webrtcEnabled: fingerprint.enable_webrtc_spoof !== false,
    mediaDevicesEnabled: fingerprint.enable_webrtc_spoof !== false,
    gamepadEnabled: fingerprint.enable_gamepad_spoof !== false,
    speechEnabled: fingerprint.enable_speech_synthesis_spoof !== false,
    eventTimingEnabled: !stabilityMode && fingerprint.enable_performance_spoof !== false,
    automationEvasionEnabled: fingerprint.enable_automation_evasion !== false,
    geolocationEnabled: fingerprint.enable_geolocation_spoof !== false,
    privacyBlackholeEnabled: true,
    iframePropagationEnabled: fingerprint.enable_iframe_protection !== false,
  }
}

export function getPolicy() {
  return getRuntime().policy
}