import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter, mapMethod } from '../core/descriptors.js'

export function installMediaDevicesSpoof() {
  const devices = navigator.mediaDevices
  if (!devices) { markModule('mediaDevices', { status: 'unavailable' }); return }
  const fp = getFingerprint()
  const labels = { audioinput: 'Microphone', audiooutput: 'Speakers', videoinput: 'Camera' }
  replaceGetter(globalThis.MediaDeviceInfo?.prototype, 'label', (label, device) => {
    if (!label) return label
    const configured = fp.media_devices?.find((item) => item.kind === device.kind)
    return configured?.label || labels[device.kind] || label
  })
  replaceGetter(globalThis.MediaStreamTrack?.prototype, 'label', (label, track) => {
    if (!label) return label
    const kind = track.kind === 'video' ? 'videoinput' : 'audioinput'
    return fp.media_devices?.find((item) => item.kind === kind)?.label || labels[kind]
  })
  mapMethod(globalThis.MediaDeviceInfo?.prototype, 'toJSON', (result, device) => ({ ...result, label: device.label }))
  markModule('mediaDevices', { status: 'partial', detail: 'native devices, IDs, constraints and groups; permission-gated labels only' })
}
