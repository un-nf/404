import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceGetter } from '../core/descriptors.js'

function defineScreenGetter(name, fn) {
  return replaceGetter(Screen.prototype, name, () => fn())
}

function parseResolution(value) {
  const [width, height] = String(value || '1920x1080').split('x').map((part) => Number(part))
  return {
    width: Number.isFinite(width) ? width : 1920,
    height: Number.isFinite(height) ? height : 1080,
  }
}

export function installScreen() {
  const fingerprint = getFingerprint()
  const resolution = parseResolution(fingerprint.screen_resolution)

  defineScreenGetter('width', () => resolution.width)
  defineScreenGetter('height', () => resolution.height)
  defineScreenGetter('availWidth', () => fingerprint.screen_avail_width ?? resolution.width)
  defineScreenGetter('availHeight', () => fingerprint.screen_avail_height ?? (resolution.height - 40))
  defineScreenGetter('availTop', () => fingerprint.screen_avail_top ?? 0)
  defineScreenGetter('availLeft', () => fingerprint.screen_avail_left ?? 0)
  defineScreenGetter('colorDepth', () => fingerprint.color_depth ?? 24)
  defineScreenGetter('pixelDepth', () => fingerprint.pixel_depth ?? fingerprint.color_depth ?? 24)
  defineScreenGetter('isExtended', () => fingerprint.screen_is_extended ?? false)

  if (screen.orientation) {
    const proto = Object.getPrototypeOf(screen.orientation)
    replaceGetter(proto, 'type', () => fingerprint.screen_orientation_type || 'landscape-primary')
    replaceGetter(proto, 'angle', () => fingerprint.screen_orientation_angle ?? 0)
  }
  replaceGetter(window, 'devicePixelRatio', () => fingerprint.device_pixel_ratio ?? 1)

  markModule('screen')
}