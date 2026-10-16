const { test } = require('node:test')
const assert = require('node:assert/strict')
const esbuild = require('../build/node_modules/esbuild')
const vm = require('node:vm')
const path = require('node:path')
const source = esbuild.build({ entryPoints: [path.join(__dirname, '../assets/js/src/core/descriptors.js')],
  bundle: true, format: 'cjs', write: false }).then((r) => r.outputFiles[0].text)
async function helpers() {
  const context = vm.createContext({ module: { exports: {} } })
  vm.runInContext(await source, context)
  return context.module.exports
}

test('getter wrapper preserves genuine brand check, owner, flags, setter and metadata', async () => {
  const { replaceGetter } = await helpers()
  const state = new WeakMap()
  const getter = { get value() { if (!state.has(this)) throw new TypeError('Illegal invocation'); return state.get(this) } }
  const setter = function (value) { state.set(this, value) }
  const proto = {}
  Object.defineProperty(proto, 'value', { get: Object.getOwnPropertyDescriptor(getter, 'value').get,
    set: setter, configurable: true, enumerable: false })
  const object = Object.create(proto); state.set(object, 4)
  const before = Object.getOwnPropertyDescriptor(proto, 'value')
  assert.equal(replaceGetter(object, 'value', (x) => x + 1), true)
  const after = Object.getOwnPropertyDescriptor(proto, 'value')
  assert.equal(object.value, 5)
  assert.equal(Object.hasOwn(object, 'value'), false)
  assert.equal(after.set, setter)
  assert.equal(after.enumerable, before.enumerable)
  assert.equal(after.get.name, before.get.name)
  assert.equal(after.get.length, before.get.length)
  assert.equal(Object.hasOwn(after.get, 'prototype'), false)
  assert.throws(() => Reflect.apply(after.get, {}, []), TypeError)
  object.value = 7; assert.equal(object.value, 8)
})

test('methods preserve symbols, argument identity, receiver, errors and constructability', async () => {
  const { mapMethod } = await helpers()
  const key = Symbol('method'); const token = {}; const expected = {}
  const proto = { [key](value) { if (this !== expected) throw new TypeError('Illegal invocation'); assert.equal(value, token); return value } }
  const before = Object.getOwnPropertyDescriptor(proto, key)
  mapMethod(proto, key, (value) => value)
  const after = Object.getOwnPropertyDescriptor(proto, key)
  assert.equal(Reflect.apply(after.value, expected, [token]), token)
  assert.equal(after.value.name, before.value.name)
  assert.equal(after.value.length, before.value.length)
  assert.equal(after.enumerable, before.enumerable)
  assert.throws(() => Reflect.apply(after.value, {}, [token]), TypeError)
  assert.throws(() => new after.value(), TypeError)
})

test('unsupported and fixed descriptors are not manufactured or partially redefined', async () => {
  const { replaceGetter, replaceMethod } = await helpers()
  const target = {}; Object.defineProperty(target, 'fixed', { get() { return 3 } })
  assert.equal(replaceGetter(target, 'absent', () => 1), false)
  assert.equal(replaceGetter(target, 'fixed', () => 1), false)
  assert.equal(replaceMethod(target, 'absent', () => 1), false)
  assert.deepEqual(Object.getOwnPropertyNames(target), ['fixed'])
  assert.equal(target.fixed, 3)
})

test('lenient native getters retain undefined for unsupported/illegal receivers', async () => {
  const { replaceGetter } = await helpers()
  const object = {}
  const proto = { get value() { return this === object ? 5 : undefined } }
  replaceGetter(proto, 'value', () => 7)
  const getter = Object.getOwnPropertyDescriptor(proto, 'value').get
  assert.equal(getter.call(object), 7)
  assert.equal(getter.call({}), undefined)
})

test('clock coarsening is monotonic and idempotent at binary/decimal boundaries', async () => {
  const built = await esbuild.build({ entryPoints: [path.join(__dirname, '../assets/js/src/core/clock.js')],
    bundle: true, format: 'cjs', write: false })
  const context = vm.createContext({module:{exports:{}}}); vm.runInContext(built.outputFiles[0].text, context)
  const { coarsenTime } = context.module.exports
  const input = [0,0.1,0.299999999,70.6,70.61,70.699,256.9,1000000000.9]
  const output = input.map(coarsenTime)
  assert.ok(output.every((value, i) => i === 0 || value >= output[i-1]))
  assert.ok(output.every((value) => coarsenTime(value) === value))
})
