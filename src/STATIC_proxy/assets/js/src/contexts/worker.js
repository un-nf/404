import { installModule } from '../core/installer.js'
import { initRuntime, finishRuntime, getRuntime, markModule } from '../core/guard.js'
import { loadConfig } from '../core/config.js'
import { installToStringProxy } from '../core/toString.js'
import { installNavigator } from '../identity/navigator.js'
import { installNetwork } from '../capabilities/network.js'
import { installPerformance } from '../identity/performance.js'
import { installTimezone } from '../identity/timezone.js'
import { installWebGLSpoof } from '../spoofing/webgl.js'
import { initPolicy, getPolicy } from '../core/policy.js'
import { installEventTimingSpoof } from '../spoofing/event-timing.js'
import { installStorage } from '../capabilities/storage.js'
import { installPermissions } from '../capabilities/permissions.js'
import { installNotifications } from '../capabilities/notifications.js'
import { installMediaCapabilities } from '../capabilities/media-capabilities.js'
import { initEntropy } from '../core/entropy.js'
import { installCanvasSpoof } from '../spoofing/canvas.js'

export function startWorker(fingerprint) {
  if (typeof WorkerGlobalScope !== 'function' || !(globalThis instanceof WorkerGlobalScope)) return 'unavailable'
  if (!initRuntime()) return getRuntime().state
  try {
    if (!getRuntime().config?.ready) loadConfig({ fingerprint: { ...fingerprint, canvas_hash: 'unused-worker',
      webgl_vendor: fingerprint.webgl_vendor || 'unused-worker', webgl_renderer: fingerprint.webgl_renderer || 'unused-worker' } })
    if (!getRuntime().nativeRefs.functionToString) getRuntime().nativeRefs = Object.freeze({ functionToString: Function.prototype.toString, intlDateTimeFormat: Intl.DateTimeFormat })
    installModule('toString', true, installToStringProxy)
    initPolicy()
    if (!getRuntime().entropy) initEntropy()
    const policy = getPolicy()
    installModule('navigator', true, installNavigator)
    installModule('permissions', policy.permissionsEnabled, installPermissions)
    installModule('notifications', policy.notificationsEnabled, installNotifications)
    installModule('storage', policy.storageEnabled, installStorage)
    installModule('mediaCapabilities', policy.mediaCapabilitiesEnabled, installMediaCapabilities)
    installModule('network', policy.networkEnabled, installNetwork)
    installModule('performance', policy.performanceEnabled, installPerformance)
    installModule('eventTiming', policy.eventTimingEnabled, installEventTimingSpoof)
    installModule('timezone', policy.timezoneEnabled, installTimezone)
    installModule('canvas', policy.canvasEnabled && Boolean(globalThis.OffscreenCanvas), installCanvasSpoof)
    installModule('webgl', policy.webglEnabled && Boolean(fingerprint.webgl_vendor && fingerprint.webgl_renderer), installWebGLSpoof)
    markModule('worker', { status: 'partial', detail: 'identity/network, storage/permissions/media/notifications where present, clock, default timezone and WebGL metadata; canvas pixels/audio uncovered' })
    finishRuntime()
    return getRuntime().state
  } catch (error) {
    finishRuntime(error)
    console.error('[STATIC] worker initialization failed:', error.message)
    return 'failed'
  }
}
