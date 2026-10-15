const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..'),profile=require('../profiles/chrome-windows.json')
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/guard.js';export * from './assets/js/src/core/config.js';export * from './assets/js/src/identity/plugins.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
async function setup(enabled,uniform,policy){const context=vm.createContext({module:{exports:{}},DOMException,uniform});vm.runInContext(await source,context);const api=context.module.exports;api.initRuntime();api.loadConfig({...profile,fingerprint:{...profile.fingerprint,pdf_viewer_enabled:enabled,...(policy?{pdf_inventory_policy:policy}:{})}})
 vm.runInContext(`
 class Plugin {constructor(name){this.name=name}get filename(){if(!(this instanceof Plugin))throw TypeError('receiver');return 'host-private-filename'}get description(){return 'host-description'}}
 class MimeType {constructor(type){this.type=type}get suffixes(){return 'host-suffix'}get description(){return 'host-description'}}
 const p=['PDF Viewer','Chrome PDF Viewer','Chromium PDF Viewer','Microsoft Edge PDF Viewer','WebKit built-in PDF'].map(name=>new Plugin(name)),m=['application/pdf','text/pdf'].map(type=>new MimeType(type));
 if(!uniform)p.push(new Plugin('host-secret'));
 class Navigator {get plugins(){if(!(this instanceof Navigator))throw TypeError('receiver');return p}get mimeTypes(){return m}get pdfViewerEnabled(){return true}}
 Object.assign(globalThis,{Plugin,MimeType,navigator:new Navigator()});beforePlugins=navigator.plugins;`,context)
 api.installPlugins();return {context,api}}
test('standardized PDF cohort keeps genuine objects and normalizes host metadata',async()=>{
 const {context}=await setup(true,true)
 assert.equal(vm.runInContext('navigator.plugins===beforePlugins',context),true)
 assert.equal(vm.runInContext('navigator.plugins[0].filename',context),'internal-pdf-viewer')
 assert.equal(vm.runInContext('navigator.mimeTypes[0].suffixes',context),'pdf')
 assert.equal(vm.runInContext('navigator.pdfViewerEnabled',context),true)
 assert.throws(()=>vm.runInContext('Object.getOwnPropertyDescriptor(Navigator.prototype,"plugins").get.call({})',context),/receiver/)
})
test('mismatching and disabled PDF inventories are denied rather than exposed',async()=>{
 for(const [enabled,uniform]of [[true,false],[false,true]]){const {context}=await setup(enabled,uniform)
  for(const key of ['plugins','mimeTypes'])assert.throws(()=>vm.runInContext('navigator.'+key,context),error=>error.name==='SecurityError')
  if(enabled)assert.throws(()=>vm.runInContext('navigator.pdfViewerEnabled',context),error=>error.name==='SecurityError')
  else assert.equal(vm.runInContext('navigator.pdfViewerEnabled',context),false)
 }
})

test('R10 explicit uniform denial follows the profile flag across host cohorts without claiming collection parity',async()=>{for(const uniform of [true,false]){const {context}=await setup(true,uniform,'deny');assert.equal(vm.runInContext('navigator.pdfViewerEnabled',context),true);for(const key of ['plugins','mimeTypes'])assert.throws(()=>vm.runInContext('navigator.'+key,context),error=>error.name==='SecurityError');}})
