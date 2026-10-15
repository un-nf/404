const esbuild = require('esbuild')
const fs = require('fs')
const path = require('path')
const { createHash } = require('node:crypto')

const root = __dirname
const entryPoint = path.join(root, '..', 'assets', 'js', 'src', 'runtime.js')
const outfile = process.env.STATIC_BUNDLE_OUTFILE || path.join(root, '..', 'assets', 'js', 'dist', 'runtime.bundle.js')
const outdir = path.dirname(outfile)
const watch = process.argv.includes('--watch')
const sourceFiles=(directory,relative='')=>fs.readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
  const name=path.posix.join(relative,entry.name);if(name==='capabilities/Website')return [];
  return entry.isDirectory()?sourceFiles(path.join(directory,entry.name),name):entry.isFile()&&name.endsWith('.js')?[name]:[];
}).sort();

fs.mkdirSync(outdir, { recursive: true })

const config = {
  absWorkingDir: path.resolve(root, '..'),
  entryPoints: [entryPoint],
  bundle: true,
  format: 'iife',
  globalName: 'staticRuntimeModule',
  banner: { js: '(function () {\n"use strict";\nfunction createStaticRealmRuntime() {\n"use strict";' },
  footer: { js: `
return staticRuntimeModule.startRuntime
}
const nativeToString = Function.prototype.toString
const apply = Reflect.apply
const weakHas = WeakMap.prototype.has, weakGet = WeakMap.prototype.get, weakSet = WeakMap.prototype.set
const has = (map,key) => apply(weakHas,map,[key])
const get = (map,key) => apply(weakGet,map,[key])
const set = (map,key,value) => apply(weakSet,map,[key,value])
const factorySource = apply(nativeToString,createStaticRealmRuntime,[])
const documents = new WeakMap()
const realms = new WeakMap()
function initializeChild(child, doc, rawConfig) {
  if (has(documents,doc) && get(documents,doc) !== 'failed') return get(documents,doc)
  set(documents,doc, 'initializing')
  try {
    const realmKey = child.Object
    if (typeof realmKey !== 'function') return 'unsupported'
    if (has(realms,realmKey)) {
      const instance = get(realms,realmKey)
      const outcome = instance.outcome === 'failed' ? instance.start(rawConfig, initializeChild) : instance.outcome
      instance.outcome = outcome
      set(documents,doc, outcome)
      return outcome
    }
    const start = child.Function('return (' + factorySource + ')()')()
    const outcome = start(rawConfig, initializeChild)
    set(realms,realmKey, {start, outcome})
    set(documents,doc, outcome)
    return outcome
  } catch {
    set(documents,doc, 'unsupported')
    return 'unsupported'
  }
}
set(documents,document, 'initializing')
const rootStart = createStaticRealmRuntime()
const rootOutcome = rootStart(undefined, initializeChild)
set(documents,document, rootOutcome)
set(realms,Object, {start:rootStart, outcome:rootOutcome})
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
  banner: { js: '(function (fingerprint) {\n"use strict";' },
  footer: { js: 'workerRuntimeModule.startWorker(fingerprint)\n})' },
}
const workerModuleConfig = {
  ...config, entryPoints: [path.join(root, '..', 'assets/js/src/contexts/worker-module.js')],
  outfile: path.join(outdir, 'worker-module.bundle.js'), format: 'esm', globalName: undefined,
  banner: undefined, footer: undefined,
}

async function main() {
  if(process.argv.includes('--verify')){
    const metadata=JSON.parse(fs.readFileSync(path.join(outdir,'bundle-set.json')));
    const digest=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    for(const [file,hash]of Object.entries(metadata.bundles))if(digest(path.join(outdir,file))!==hash)throw Error('Mismatched bundle set: '+file);
    for(const [file,hash]of Object.entries(metadata.schemas))if(digest(path.join(root,'../schema',file))!==hash)throw Error('Stale schema dependency: '+file);
    const sources=sourceFiles(path.join(root,'../assets/js/src'));
    if(sources.length!==Object.keys(metadata.sources).length)throw Error('Source inventory differs from bundle set');
    for(const file of sources)if(digest(path.join(root,'../assets/js/src',file))!==metadata.sources[file])throw Error('Stale JavaScript source: '+file);
    if(digest(path.join(root,'package-lock.json'))!==metadata.lockfile)throw Error('Stale bundle dependency lock');
    if(digest(__filename)!==metadata.builder)throw Error('Stale bundle build script');
    return;
  }
  if (watch) {
    const {spawn}=require('node:child_process');let running=false,again=false,timer;
    const rebuild=()=>{if(running){again=true;return;}running=true;const child=spawn(process.execPath,[__filename],{stdio:'inherit',windowsHide:true});child.on('exit',()=>{running=false;if(again){again=false;rebuild();}});};
    const changed=(_event,name)=>{if(name?.toString().replaceAll('\\','/').startsWith('capabilities/Website/'))return;clearTimeout(timer);timer=setTimeout(rebuild,100);};
    fs.watch(path.join(root,'../assets/js/src'),{recursive:true},changed);
    fs.watch(path.join(root,'../schema'),changed);
    fs.watch(root,(_event,name)=>{if(['build.js','package.json','package-lock.json'].includes(name?.toString()))changed();});
    rebuild();
    return
  }

  const stage=fs.mkdtempSync(path.join(outdir,'.static-build-'))
  try {
    const settings=[config,workerClassicConfig,workerModuleConfig]
    const results=await Promise.allSettled(settings.map(item=>esbuild.build({...item,outfile:path.join(stage,path.basename(item.outfile))})))
    const failed=results.find(result=>result.status==='rejected')
    if(failed)throw failed.reason
    const files=settings.map(item=>path.basename(item.outfile))
    const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex')
    const locked=JSON.parse(fs.readFileSync(path.join(root,'package-lock.json'))).packages['node_modules/esbuild'].version;
    if(esbuild.version!==locked)throw Error('Installed esbuild differs from package-lock.json; run npm ci');
    const metadata={schema:1,bundles:Object.fromEntries(files.map(file=>[file,hash(path.join(stage,file))])),
      builder:hash(__filename),lockfile:hash(path.join(root,'package-lock.json')),schemas:Object.fromEntries(fs.readdirSync(path.join(root,'../schema')).filter(file=>file.endsWith('.json')).map(file=>[file,hash(path.join(root,'../schema',file))])),
      sources:Object.fromEntries(sourceFiles(path.join(root,'../assets/js/src')).map(file=>[file,hash(path.join(root,'../assets/js/src',file))])),
      renderingClaim:'observations-only',completeParity:false}
    for(const file of files)fs.renameSync(path.join(stage,file),path.join(outdir,file))
    const manifest=path.join(stage,'bundle-set.json');fs.writeFileSync(manifest,JSON.stringify(metadata,null,2)+'\n')
    fs.renameSync(manifest,path.join(outdir,'bundle-set.json'))
  } finally { fs.rmSync(stage,{recursive:true,force:true}) }
}

module.exports = config

if (require.main === module) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
