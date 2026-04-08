import { getRuntime } from './guard.js'

const nativeCodeRegistry = new WeakMap()

export function markNativeCode(fn, name) {
  nativeCodeRegistry.set(fn, name || fn.name || 'anonymous')
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
        return `function ${nativeCodeRegistry.get(thisArg)}() { [native code] }`
      }
      return Reflect.apply(target, thisArg, args)
    },
  })

  nativeCodeRegistry.set(toStringProxy, 'toString')

  Object.defineProperty(Function.prototype, 'toString', {
    value: toStringProxy,
    configurable: true,
    writable: true,
    enumerable: false,
  })
}