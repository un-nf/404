import { getRuntime, markModule } from '../core/guard.js'
import { getFingerprint } from '../core/config.js'
import { markNativeCode } from '../core/toString.js'

function computeOffsetMinutes(timeZone) {
  try {
    const now = new Date()
    const localeValue = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(now)
    const utcValue = new Intl.DateTimeFormat('en-US', {
      timeZone: 'UTC',
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(now)
    return (new Date(utcValue) - new Date(localeValue)) / 60000
  } catch {
    return 0
  }
}

export function installTimezone() {
  const runtime = getRuntime()
  const fingerprint = getFingerprint()
  const timeZone = fingerprint.timezone

  if (!timeZone) {
    return
  }

  const offsetMinutes = Number.isFinite(fingerprint.timezone_offset)
    ? fingerprint.timezone_offset
    : computeOffsetMinutes(timeZone)

  Object.defineProperty(Date.prototype, 'getTimezoneOffset', {
    value: markNativeCode(function getTimezoneOffset() {
      return offsetMinutes
    }, 'getTimezoneOffset'),
    configurable: true,
    writable: true,
    enumerable: false,
  })

  const NativeDateTimeFormat = runtime.nativeRefs.intlDateTimeFormat
  function DateTimeFormat(locales, options) {
    return new NativeDateTimeFormat(locales, { ...(options || {}), timeZone })
  }
  DateTimeFormat.prototype = NativeDateTimeFormat.prototype
  DateTimeFormat.supportedLocalesOf = NativeDateTimeFormat.supportedLocalesOf.bind(NativeDateTimeFormat)
  markNativeCode(DateTimeFormat, 'DateTimeFormat')
  Intl.DateTimeFormat = DateTimeFormat

  markModule('timezone')
}