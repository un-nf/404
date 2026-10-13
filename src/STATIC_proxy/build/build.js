const esbuild = require('esbuild')
const fs = require('fs')
const path = require('path')

const root = __dirname
const entryPoint = path.join(root, '..', 'assets', 'js', 'src', 'runtime.js')
const outfile = process.env.STATIC_BUNDLE_OUTFILE || path.join(root, '..', 'assets', 'js', 'dist', 'runtime.bundle.js')
const outdir = path.dirname(outfile)
const watch = process.argv.includes('--watch')

fs.mkdirSync(outdir, { recursive: true })

const config = {
  absWorkingDir: path.resolve(root, '..'),
  entryPoints: [entryPoint],
  bundle: true,
  format: 'iife',
  globalName: 'staticRuntimeModule',
  banner: { js: '(function () {\nfunction createStaticRealmRuntime() {' },
  footer: { js: `
return staticRuntimeModule.startRuntime
}
const nativeToString = Function.prototype.toString
const factorySource = nativeToString.call(createStaticRealmRuntime)
const documents = new WeakMap()
const realms = new WeakMap()
function initializeChild(child, doc, rawConfig) {
  if (documents.has(doc) && documents.get(doc) !== 'failed') return documents.get(doc)
  documents.set(doc, 'initializing')
  try {
    const realmKey = child.Object
    if (typeof realmKey !== 'function') return 'unsupported'
    if (realms.has(realmKey)) {
      const instance = realms.get(realmKey)
      const outcome = instance.outcome === 'failed' ? instance.start(rawConfig, initializeChild) : instance.outcome
      instance.outcome = outcome
      documents.set(doc, outcome)
      return outcome
    }
    const start = child.Function('return (' + factorySource + ')()')()
    const outcome = start(rawConfig, initializeChild)
    realms.set(realmKey, {start, outcome})
    documents.set(doc, outcome)
    return outcome
  } catch {
    documents.set(doc, 'unsupported')
    return 'unsupported'
  }
}
documents.set(document, 'initializing')
const rootStart = createStaticRealmRuntime()
const rootOutcome = rootStart(undefined, initializeChild)
documents.set(document, rootOutcome)
realms.set(Object, {start:rootStart, outcome:rootOutcome})
})()
` },
  outfile,
  minify: false,
  sourcemap: false,
  target: ['chrome120', 'firefox120', 'safari17'],
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  logLevel: 'info',
}

const workerClassicConfig = {
  ...config, entryPoints: [path.join(root, '..', 'assets/js/src/contexts/worker.js')],
  outfile: path.join(outdir, 'worker-classic.bundle.js'), globalName: 'workerRuntimeModule',
  banner: { js: '(function (fingerprint) {' },
  footer: { js: 'workerRuntimeModule.startWorker(fingerprint)\n})' },
}
const workerModuleConfig = {
  ...config, entryPoints: [path.join(root, '..', 'assets/js/src/contexts/worker-module.js')],
  outfile: path.join(outdir, 'worker-module.bundle.js'), format: 'esm', globalName: undefined,
  banner: undefined, footer: undefined,
}

async function main() {
  if (watch) {
    for (const settings of [config, workerClassicConfig, workerModuleConfig]) {
      const ctx = await esbuild.context(settings)
      await ctx.watch()
    }
    return
  }

  await Promise.all([config, workerClassicConfig, workerModuleConfig].map((settings) => esbuild.build(settings)))
}

module.exports = config

if (require.main === module) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
