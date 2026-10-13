const assert = require('node:assert/strict')
const { test } = require('node:test')
const vm = require('node:vm')
const path = require('node:path')
const fs = require('node:fs')
const esbuild = require('../build/node_modules/esbuild')
const options = require('../build/build.js')
const root = path.resolve(__dirname, '..')

const publicKeys = ['__STATIC_RUNTIME__', '__STATIC_CONFIG__', '__STATIC_FINGERPRINT__',
  '__fpConfig', '__static_rng', '__static_hash', '__STATIC_CSP_NONCE', '__404_canvas_fingerprint']

const harness = esbuild.build({
  stdin: { contents: `export * from './assets/js/src/core/guard.js';
    export * from './assets/js/src/core/config.js';
    export * from './assets/js/src/core/entropy.js';
    export * from './assets/js/src/core/nonce.js';
    export * from './assets/js/src/core/native-refs.js';
    export * from './assets/js/src/contexts/iframe.js';`, resolveDir: root },
  bundle: true, format: 'cjs', write: false, logLevel: 'silent',
}).then((r) => r.outputFiles[0].text)
const production = esbuild.build({ ...options, write: false, logLevel: 'silent' })
  .then((r) => r.outputFiles[0].text)

function profile() {
  return { startup_salt: 'private-test-salt', fingerprint: {
    user_agent: 'Mozilla/5.0 Windows AppleWebKit/537.36 Chrome/147.0.0.0',
    platform: 'Win32', vendor: 'Google Inc.', browser_variant: 'chrome',
    canvas_hash: 'private-canvas-seed', webgl_vendor: 'vendor', webgl_renderer: 'renderer', webgl_contexts:require('../profiles/chrome-windows.json').fingerprint.webgl_contexts,
    ua_data: { brands: [{ brand: 'Chromium', version: '147' }], full_version_list:[{brand:'Chromium',version:'147.0.0.0'}],
      platform:'Windows',platform_version:'15.0.0',architecture:'x86',bitness:'64',model:'',ua_full_version:'147.0.0.0',mobile:false,wow64:false,form_factors:['Desktop'] },
  } }
}

function realm(raw = profile()) {
  const attributes = new Map([['data-static-config-b64', Buffer.from(JSON.stringify(raw)).toString('base64')]])
  let observer
  const frames = []
  const script = { nonce: 'document-nonce', getAttribute: (key) => attributes.get(key),
    removeAttribute: (key) => attributes.delete(key) }
  const context = vm.createContext({ console: { warn() {}, error() {} }, TextDecoder, URL,
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
    document: { currentScript: script, documentElement: {}, scripts: [script],
      getElementById: () => null, querySelectorAll: () => frames },
    location: { origin: 'https://one.test', hostname: 'one.test' },
    MutationObserver: class { constructor(fn) { observer = fn } observe() {} },
  })
  vm.runInContext(`window = globalThis;
    class Navigator {}; navigator = new Navigator();
    screen = {}; performance = { now() { return 100 } };
    class Document { hasFocus() { return true } };
    class CanvasRenderingContext2D { getImageData() { return { data: [3, 4, 5, 255] } } };
    window.CanvasRenderingContext2D = CanvasRenderingContext2D;
    window.Document = Document; window.Navigator = Navigator;
  `, context)
  return { context, attributes, frames, mutate: (mutations) => observer(mutations) }
}

async function services(raw) {
  const fixture = realm(raw)
  fixture.context.module = { exports: {} }
  vm.runInContext(await harness, fixture.context)
  fixture.api = fixture.context.module.exports
  return fixture
}

test('private services cannot be discovered through window property names', async () => {
  const { context, api } = await services()
  assert.equal(api.initRuntime(), true)
  api.loadConfig(profile()); api.captureNativeRefs(); api.initEntropy(); api.captureNonce()
  const names = Object.getOwnPropertyNames(context)
  for (const key of publicKeys) assert.equal(names.includes(key), false, key)
  assert.equal(api.getRuntime().nativeRefs.canvasGetImageData.call({}).data[0], 3)
  assert.equal(api.getRuntime().nonce, 'document-nonce')
  assert.equal(Object.isFrozen(api.getRuntime().nativeRefs), true)
  assert.equal(api.initRuntime(), false)
})

test('xorshift output excludes 1 even for the predecessor of all-one bits', async () => {
  const { api } = await services(); api.initRuntime(); api.loadConfig(profile()); api.initEntropy()
  function undo(value, shift, left) {
    let result = value
    for (let i = 0; i < 32; i++) result = value ^ (left ? result << shift : result >>> shift)
    return result >>> 0
  }
  const seed = undo(undo(undo(0xffffffff, 5, true), 17, false), 13, true)
  assert.equal(api.getRuntime().entropy.rng(seed)(), 0xffffffff / 0x100000000)
})

test('page-preseeded runtime, persona, RNG and nonce globals are ignored', async () => {
  const { context, api } = await services()
  context.__STATIC_RUNTIME__ = { version: '5.0.0', nativeRefs: { attacker: true } }
  context.__fpConfig = { user_agent: 'attacker' }
  context.__static_rng = () => 1
  context.__STATIC_CSP_NONCE = 'attacker-nonce'
  assert.equal(api.initRuntime(), true)
  api.loadConfig(profile()); api.initEntropy()
  context.document.currentScript = null
  assert.equal(api.captureNonce(), null)
  assert.equal(api.getFingerprint().platform, 'Win32')
  assert.notEqual(api.getRuntime(), context.__STATIC_RUNTIME__)
  assert.equal(api.getRuntime().nativeRefs.attacker, undefined)
})

test('persona is an independent deeply frozen snapshot', async () => {
  const { api } = await services()
  api.initRuntime()
  const input = profile(); api.loadConfig(input)
  input.fingerprint.ua_data.brands[0].brand = 'attacker'
  const fp = api.getFingerprint()
  assert.equal(fp.ua_data.brands[0].brand, 'Chromium')
  assert.equal(Object.isFrozen(fp), true)
  assert.equal(Object.isFrozen(fp.ua_data.brands), true)
  assert.equal(Object.isFrozen(fp.ua_data.brands[0]), true)
  assert.equal(Reflect.set(fp, 'platform', 'attacker'), false)
})

test('UTF-8 bootstrap is decoded and its DOM input consumed', async () => {
  const raw = profile(); raw.fingerprint.name = 'Hawaiʻi 中文'
  const { api, attributes } = await services(raw)
  api.initRuntime(); api.loadConfig()
  assert.equal(api.getFingerprint().name, raw.fingerprint.name)
  assert.equal(attributes.has('data-static-config-b64'), false)
})

test('invalid encoded input does not fall back to an unrelated profile', async () => {
  const { api, attributes } = await services()
  attributes.set('data-static-config-b64', '////')
  api.initRuntime()
  assert.throws(() => api.loadConfig(), /encoded profile is invalid/)
  assert.equal(api.getRuntime().config, null)
})

test('missing values, conflicting families, invalid flags and unsafe strides reject before patching', async () => {
  for (const mutate of [
    (p) => delete p.fingerprint.user_agent,
    (p) => { p.fingerprint.platform = 12 },
    (p) => { p.fingerprint.browser_family = 'firefox-like' },
    (p) => { p.fingerprint.enable_canvas_spoof = 'false' },
    (p) => { p.fingerprint.canvas_noise = { default_stride: 0 } },
    (p) => { p.fingerprint.languages = [7] },
    (p) => { p.fingerprint.ua_data = { brands: [{ brand: 7, version: '1' }] } },
    (p) => { p.fingerprint.hardware_concurrency = -1 },
  ]) {
    const raw = profile(); mutate(raw)
    const { api } = await services(); api.initRuntime()
    assert.throws(() => api.loadConfig(raw), /STATIC/)
    assert.equal(api.getRuntime().config, null)
  }
})

test('the three shipped base profiles satisfy C1 preflight', async () => {
  for (const name of ['chrome', 'edge', 'firefox']) {
    const raw = JSON.parse(fs.readFileSync(path.join(root, 'profiles', `${name}-windows.json`), 'utf8'))
    const { api } = await services(); api.initRuntime(); api.loadConfig(raw)
    assert.equal(api.getConfig().ready, true)
  }
})

test('production bundle failure leaves Function.toString and navigator untouched', async () => {
  const { context } = realm({ fingerprint: {} })
  const before = vm.runInContext('Function.prototype.toString', context)
  vm.runInContext(await production, context)
  assert.equal(vm.runInContext('Function.prototype.toString', context), before)
  assert.equal(vm.runInContext("Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent')", context), undefined)
  for (const key of publicKeys) assert.equal(Object.hasOwn(context, key), false)
  assert.equal(Object.hasOwn(context, 'staticRuntimeModule'), false)
  assert.equal(Object.hasOwn(context, 'createStaticRealmRuntime'), false)
})

test('nested frame insertion and repeat navigation initialize privately without copying descriptors', async () => {
  const { context, api, mutate } = await services()
  api.initRuntime(); api.loadConfig(profile())
  const calls = []
  api.installIframePropagation((child, doc, raw) => { calls.push({ child, doc, raw }); return 'ready' })
  const listeners = {}
  const child = { navigator: {} }; const doc = { scripts: [], baseURI: 'https://one.test/' }
  const frame = { nodeType: 1, localName: 'iframe', contentWindow: child, contentDocument: doc,
    addEventListener(name, fn, options) { listeners[name] = fn; assert.equal(options?.once, undefined) },
    querySelectorAll() { return [] } }
  mutate([{ addedNodes: [{ nodeType: 1, localName: 'div', querySelectorAll() { return [frame] } }] }])
  assert.equal(calls.length, 1)
  frame.contentDocument = { ...doc }; listeners.load()
  assert.equal(calls.length, 2)
  assert.deepEqual(Object.keys(child), ['navigator'])
  assert.equal(Object.keys(child.navigator).length, 0)
  assert.equal(api.getRuntime().frames.get(frame), 'ready')
})

test('restricted frames and unavailable bootstrap are recorded without claiming success', async () => {
  const { api, frames } = await services()
  api.initRuntime(); api.loadConfig(profile())
  const restricted = { addEventListener() {}, get contentDocument() { throw new Error('restricted') }, contentWindow: {} }
  const unsupported = { addEventListener() {}, contentWindow: {}, contentDocument: { scripts: [] } }
  frames.push(restricted, unsupported)
  api.installIframePropagation()
  assert.equal(api.getRuntime().frames.get(restricted), 'unavailable')
  assert.equal(api.getRuntime().frames.get(unsupported), 'unsupported')
})
