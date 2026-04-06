import { getRuntime, markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function defineMethod(target, name, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, {
    value: fn,
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? false,
  })
}

function cloneGamepad(runtime, pad, index) {
  const source = pad && typeof pad === 'object' ? pad : {}
  const key = `${source.id || 'gamepad'}:${index}:${runtime.entropy.sessionId}`
  const axes = Array.isArray(source.axes)
    ? source.axes.slice()
    : (source.axes && typeof source.axes.length === 'number' ? Array.from(source.axes) : [])
  const buttons = Array.isArray(source.buttons)
    ? source.buttons
    : (source.buttons && typeof source.buttons.length === 'number' ? Array.from(source.buttons) : [])

  return Object.freeze({
    id: `Static-${runtime.entropy.hash(key).toString(16).padStart(8, '0')}`,
    index: typeof source.index === 'number' ? source.index : index,
    mapping: source.mapping || 'standard',
    connected: source.connected !== false,
    timestamp: typeof source.timestamp === 'number' ? source.timestamp : Date.now(),
    axes: Object.freeze(axes.map((value) => Number.isFinite(value) ? value : 0)),
    buttons: Object.freeze(buttons.map((button) => Object.freeze({
      pressed: Boolean(button?.pressed),
      touched: Boolean(button?.touched),
      value: typeof button?.value === 'number' ? button.value : 0,
    }))),
    hand: source.hand || 'unknown',
  })
}

export function installGamepadSpoof() {
  const runtime = getRuntime()
  if (!runtime.nativeRefs.getGamepads || runtime.modules.gamepad) {
    return
  }

  defineMethod(runtime.nativeRefs.NavigatorPrototype, 'getGamepads', markNativeCode(function getGamepads() {
    const pads = runtime.nativeRefs.getGamepads.apply(this, arguments)
    if (!pads) {
      return pads
    }
    return Array.prototype.map.call(pads, (pad, index) => cloneGamepad(runtime, pad, index))
  }, 'getGamepads'))

  markModule('gamepad')
}