import { getRuntime, markModule } from '../core/guard.js'
import { getFingerprint } from '../core/config.js'
import { replaceMethod } from '../core/descriptors.js'
import { markNativeLike } from '../core/toString.js'

export function installTimezone() {
  const zone = getFingerprint().timezone
  if (!zone) { markModule('timezone', { status: 'disabled' }); return }
  const Native = getRuntime().nativeRefs.intlDateTimeFormat
  const partsFormatter = new Native('en-US', { timeZone: zone, calendar: 'iso8601', numberingSystem: 'latn',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23', era: 'short' })
  const getTime = Date.prototype.getTime
  replaceMethod(Date.prototype, 'getTimezoneOffset', (native, receiver, args) => {
    const value = Reflect.apply(native, receiver, args)
    if (!Number.isFinite(value)) return value
    const instant = Reflect.apply(getTime, receiver, [])
    const parts = Object.fromEntries(partsFormatter.formatToParts(instant).map((p) => [p.type, p.value]))
    const local = new Date(0)
    local.setUTCFullYear(parts.era === 'BC' ? 1 - Number(parts.year) : Number(parts.year), Number(parts.month) - 1, Number(parts.day))
    local.setUTCHours(Number(parts.hour), Number(parts.minute), Number(parts.second), 0)
    return (Math.floor(instant / 1000) * 1000 - local.getTime()) / 60000
  })
  function defaultZone(args) {
    if (args[1] === null) return args
    const options = args[1] === undefined ? { timeZone: zone } : new Proxy(Object(args[1]), {
      get(target, key) {
        const value = Reflect.get(target, key, target)
        return key === 'timeZone' && value === undefined ? zone : value
      },
    })
    return [args[0], options, ...args.slice(2)]
  }
  const wrapped = markNativeLike(new Proxy(Native, {
    apply(native, receiver, args) { return Reflect.apply(native, receiver, defaultZone(args)) },
    construct(native, args, newTarget) { return Reflect.construct(native, defaultZone(args), newTarget) },
  }), Native)
  const descriptor = Object.getOwnPropertyDescriptor(Intl, 'DateTimeFormat')
  Object.defineProperty(Intl, 'DateTimeFormat', { ...descriptor, value: wrapped })
  const constructorDescriptor = Object.getOwnPropertyDescriptor(Native.prototype, 'constructor')
  if (constructorDescriptor?.configurable) {
    Object.defineProperty(Native.prototype, 'constructor', { ...constructorDescriptor, value: wrapped })
  }
  markModule('timezone', { status: 'partial', detail: 'Date offset/default Intl zone; explicit zones and native constructor preserved; local Date fields remain native' })
}
