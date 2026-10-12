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

export function startWorker(fingerprint) {
  if (typeof WorkerGlobalScope !== 'function' || !(globalThis instanceof WorkerGlobalScope)) return 'unavailable'
  if (!initRuntime()) return getRuntime().state
  try {
    loadConfig({ fingerprint: { ...fingerprint, canvas_hash: 'unused-worker',
      webgl_vendor: fingerprint.webgl_vendor || 'unused-worker', webgl_renderer: fingerprint.webgl_renderer || 'unused-worker' } })
    getRuntime().nativeRefs = Object.freeze({ functionToString: Function.prototype.toString, intlDateTimeFormat: Intl.DateTimeFormat })
    installToStringProxy()
    initPolicy()
    const policy = getPolicy()
    installNavigator()
    installPermissions()
    installNotifications()
    if (policy.storageEnabled) installStorage()
    if (policy.mediaCapabilitiesEnabled) installMediaCapabilities()
    if (policy.networkEnabled) installNetwork()
    if (policy.performanceEnabled) installPerformance()
    if (policy.eventTimingEnabled) installEventTimingSpoof()
    if (policy.timezoneEnabled) installTimezone()
    if (policy.webglEnabled && fingerprint.webgl_vendor && fingerprint.webgl_renderer) installWebGLSpoof()
    markModule('worker', { status: 'partial', detail: 'identity/network, storage/permissions/media/notifications where present, clock, default timezone and WebGL metadata; canvas pixels/audio uncovered' })
    finishRuntime()
    return 'ready'
  } catch (error) {
    finishRuntime(error)
    console.error('[STATIC] worker initialization failed:', error.message)
    return 'failed'
  }
}
