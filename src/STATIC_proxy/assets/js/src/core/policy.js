import { ObjectIntrinsic as Object } from './primordials.js';
import { getRuntime } from './guard.js';
import { getFingerprint } from './config.js';
export function initPolicy() {
    const runtime = getRuntime();
    const fingerprint = getFingerprint();
    const host = (() => {
        try {
            return location.hostname || new URL(globalThis.origin).hostname;
        }
        catch {
            return '';
        }
    })();
    runtime.policy = Object.freeze({
        host,
        timezoneEnabled: fingerprint.enable_timezone_spoof !== false,
        performanceEnabled: fingerprint.enable_performance_spoof !== false,
        fontMetricsEnabled: (fingerprint.enable_font_metric_spoof ?? fingerprint.enable_font_spoof) !== false,
        pluginEnabled: fingerprint.enable_plugin_spoof !== false,
        storageEnabled: fingerprint.enable_storage_spoof !== false,
        networkEnabled: fingerprint.enable_network_spoof !== false,
        mediaCapabilitiesEnabled: fingerprint.enable_media_capabilities_spoof !== false,
        permissionsEnabled: fingerprint.enable_permissions_spoof !== false,
        notificationsEnabled: fingerprint.enable_notifications_spoof !== false,
        batteryEnabled: fingerprint.enable_battery_spoof !== false,
        canvasEnabled: fingerprint.enable_canvas_spoof !== false,
        webglEnabled: fingerprint.enable_webgl_spoof !== false,
        audioEnabled: fingerprint.enable_audio_spoof !== false,
        webrtcEnabled: fingerprint.enable_webrtc_spoof !== false,
        mediaDevicesEnabled: fingerprint.enable_webrtc_spoof !== false,
        gamepadEnabled: fingerprint.enable_gamepad_spoof !== false,
        speechEnabled: fingerprint.enable_speech_synthesis_spoof !== false,
        eventTimingEnabled: fingerprint.enable_performance_spoof !== false,
        automationEvasionEnabled: fingerprint.enable_automation_evasion !== false,
        geolocationEnabled: fingerprint.enable_geolocation_spoof !== false,
        privacyBlackholeEnabled: fingerprint.enable_privacy_blackhole !== false,
        iframePropagationEnabled: fingerprint.enable_iframe_protection !== false,
    });
}
export function getPolicy() {
    return getRuntime().policy;
}
