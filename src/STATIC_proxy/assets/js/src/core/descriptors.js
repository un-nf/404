import { definePatch, skippedPatch } from './patches.js'
import { markNativeLike } from './toString.js'

export function findDescriptor(target, key) {
  for (let owner = target; owner; owner = Object.getPrototypeOf(owner)) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key)
    if (descriptor) return { owner, descriptor }
  }
  return null
}

// The genuine getter performs the internal brand check before transformation.
// Preserve ownership, setters and flags; absent host APIs stay absent.
export function replaceGetter(target, key, transform) {
  const found = findDescriptor(target, key)
  if (!found?.descriptor.get || !found.descriptor.configurable) { skippedPatch(key); return false }
  const original = found.descriptor.get
  const getter = markNativeLike(new Proxy(original, {
    apply(native, receiver, args) {
      const value = Reflect.apply(native, receiver, args)
      // LegacyLenientThis accessors can return undefined for a bad receiver.
      return value === undefined ? value : transform(value, receiver)
    },
  }), original)
  definePatch(found.owner, key, { ...found.descriptor, get: getter })
  return true
}

export function replaceMethod(target, key, intercept) {
  const found = findDescriptor(target, key)
  if (typeof found?.descriptor.value !== 'function' ||
      (!found.descriptor.configurable && !found.descriptor.writable)) { skippedPatch(key); return false }
  const original = found.descriptor.value
  const method = markNativeLike(new Proxy(original, {
    apply(native, receiver, args) { return intercept(native, receiver, args) },
  }), original)
  definePatch(found.owner, key, { ...found.descriptor, value: method })
  return true
}

export function mapMethod(target, key, transform) {
  return replaceMethod(target, key, (native, receiver, args) =>
    transform(Reflect.apply(native, receiver, args), receiver, args))
}
