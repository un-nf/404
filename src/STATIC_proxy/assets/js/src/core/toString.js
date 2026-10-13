import { definePatch } from './patches.js'
import { getRuntime } from './guard.js'

const nativeCodeRegistry = new WeakMap()

export function markNativeCode(fn, name) {
  nativeCodeRegistry.set(fn, `function ${name || fn.name || 'anonymous'}() { [native code] }`)
  return fn
}

export function markNativeLike(fn, original) {
  const toString = getRuntime()?.nativeRefs.functionToString || Function.prototype.toString
  nativeCodeRegistry.set(fn, nativeCodeRegistry.get(original) || Reflect.apply(toString, original, []))
  return fn
}

export function installToStringProxy() {
  const runtime = getRuntime()
  const nativeToString = runtime.nativeRefs.functionToString

  const toStringProxy = new Proxy(nativeToString, {
    apply(target, thisArg, args) {
      if (thisArg === toStringProxy) {
        return 'function toString() { [native code] }'
      }
      if (nativeCodeRegistry.has(thisArg)) {
        return nativeCodeRegistry.get(thisArg)
      }
      return Reflect.apply(target, thisArg, args)
    },
  })

  nativeCodeRegistry.set(toStringProxy, Reflect.apply(nativeToString, nativeToString, []))

  definePatch(Function.prototype, 'toString', {
    value: toStringProxy,
    configurable: true,
    writable: true,
    enumerable: false,
  })
}
