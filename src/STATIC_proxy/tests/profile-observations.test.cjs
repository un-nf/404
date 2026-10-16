const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),fs=require('node:fs'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..'),profile=JSON.parse(fs.readFileSync(path.join(root,'profiles/chrome-windows.json')))
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/guard.js';export * from './assets/js/src/core/config.js';export * from './assets/js/src/identity/navigator.js';export * from './assets/js/src/spoofing/webgl.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
async function setup(host){const ctx=vm.createContext({module:{exports:{}},host});vm.runInContext(await source,ctx);const api=ctx.module.exports;api.initRuntime();api.loadConfig(profile);return {ctx,api}}
test('different native GPUs expose the same exact selected limits, versions and extension observations',async()=>{
 const reports=[]
 for(const host of [64,99999]){
  const {ctx,api}=await setup(host)
  vm.runInContext(`class GL { getContextAttributes(){if(!(this instanceof GL))throw TypeError('receiver');return {}}
   getParameter(key){if(!(this instanceof GL))throw TypeError('receiver');if(key===3379)return host;if(key===3386)return new Int32Array([host,host]);if(key===7938)return 'native host version';return null}
   getSupportedExtensions(){return ['nativeExtension']}
   getExtension(name){return name==='nativeExtension'?{}:null}
   getShaderPrecisionFormat(){return null}}
   GL.prototype.MAX_TEXTURE_SIZE=3379;GL.prototype.MAX_VIEWPORT_DIMS=3386;globalThis.WebGLRenderingContext=GL;gl=new GL();`,ctx)
  api.installWebGLSpoof()
  reports.push(vm.runInContext(`JSON.stringify([GL.prototype.getParameter.call(gl,3379),Array.from(gl.getParameter(3386)),gl.getParameter(7938),gl.getSupportedExtensions()])`,ctx))
  assert.equal(vm.runInContext('gl.getParameter(3379)',ctx),profile.fingerprint.webgl_contexts.webgl1.parameters.MAX_TEXTURE_SIZE)
  assert.throws(()=>vm.runInContext('GL.prototype.getParameter.call({},3379)',ctx),/receiver/)
  assert.throws(()=>vm.runInContext('gl.getParameter(1n)',ctx),/BigInt/)
  assert.equal(vm.runInContext('gl.getParameter(123456)',ctx),null)
  vm.runInContext(`reads=0;gl.getParameter({valueOf(){reads++;return 3379}})`,ctx);assert.equal(ctx.reads,1)
 }
 assert.equal(reports[0],reports[1])
})
test('identity results mask all requested supported hints, copy string arrays and omit future native fields',async()=>{
 const {ctx,api}=await setup(0)
 vm.runInContext(`class UA { get brands(){if(!(this instanceof UA))throw TypeError('receiver');return [{brand:'host',version:'999'}]}get mobile(){return true}get platform(){return 'host'}
  getHighEntropyValues(keys){if(!(this instanceof UA))return Promise.reject(TypeError('receiver'));const r={brands:this.brands,mobile:true,platform:'host',newHardwareId:'secret'};for(const key of keys)r[key]=key==='formFactors'?['host']:key==='fullVersionList'?[{brand:'host',version:'999'}]:key==='wow64'?true:'host';return Promise.resolve(r)}toJSON(){return {brands:this.brands,mobile:true,platform:'host'}}}
  class N {get userAgentData(){return this.ua}get userAgent(){if(!(this instanceof N))throw TypeError('receiver');return 'host'}}
  navigator=new N();navigator.ua=new UA();`,ctx)
 api.installNavigator()
 const r=await vm.runInContext(`navigator.userAgentData.getHighEntropyValues(['architecture','bitness','model','platformVersion','fullVersionList','uaFullVersion','wow64','formFactors'])`,ctx)
 assert.equal(r.architecture,'x86');assert.equal(r.wow64,false);assert.deepEqual(Array.from(r.formFactors),['Desktop']);assert.equal('newHardwareId' in r,false)
 r.formFactors[0]='attacker';const again=await vm.runInContext(`navigator.userAgentData.getHighEntropyValues(['formFactors'])`,ctx);assert.equal(again.formFactors[0],'Desktop');assert.equal('architecture' in again,false)
 await assert.rejects(vm.runInContext(`UA.prototype.getHighEntropyValues.call({},[])`,ctx),/receiver/)
})

test('extension-owned WebGL limits resolve without prototype constants and preserve missing operational extensions',async()=>{
 const {ctx,api}=await setup(4)
 vm.runInContext(`class GL {getContextAttributes(){if(!(this instanceof GL))throw TypeError('receiver');return {}}getParameter(key){return [0x84ff,0x8824].includes(key)?4:null}getSupportedExtensions(){return ['EXT_texture_filter_anisotropic']}getExtension(){return null}};globalThis.WebGLRenderingContext=GL;gl=new GL();`,ctx)
 api.installWebGLSpoof()
 assert.equal(vm.runInContext('gl.getParameter(0x84ff)',ctx),16)
 assert.equal(vm.runInContext('gl.getParameter(0x8824)',ctx),8)
 assert.equal(vm.runInContext("gl.getExtension('EXT_texture_filter_anisotropic')",ctx),null)
 assert.equal(api.resolveWebGLParameter('MAX_COLOR_ATTACHMENTS_WEBGL','webgl1'),0x8cdf)
 assert.throws(()=>api.resolveWebGLParameter('NOT_A_REAL_PARAMETER','webgl1'),/unresolved/)
 assert.throws(()=>api.resolveWebGLParameter('MAX_TEXTURE_LOD_BIAS','webgl1'),/unresolved/)
})

test('Firefox persona suppresses Chromium UA-data acquisition and neutralizes retained native objects',async()=>{
 const {ctx,api}=await setup(0)
 api.loadConfig(require('../profiles/firefox-windows.json'))
 vm.runInContext(`class UA {get brands(){if(!(this instanceof UA))throw TypeError('receiver');return [{brand:'host',version:'999'}]}get mobile(){return true}get platform(){return 'host'}getHighEntropyValues(keys){if(!(this instanceof UA))return Promise.reject(TypeError('receiver'));return Promise.resolve({brands:this.brands,mobile:true,platform:'host',architecture:'native-secret',formFactors:['host'],futureDeviceId:'secret'})}toJSON(){return {brands:this.brands,mobile:true,platform:'host'}}};class N {get userAgentData(){if(!(this instanceof N))throw TypeError('receiver');return retained}get userAgent(){return 'host'}};retained=new UA();navigator=new N();`,ctx)
 api.installNavigator()
 assert.equal(vm.runInContext('navigator.userAgentData',ctx),undefined)
 const result=await vm.runInContext("retained.getHighEntropyValues(['architecture','formFactors'])",ctx)
 assert.equal(result.architecture,'');assert.equal(result.platform,'');assert.equal(result.mobile,false)
 assert.deepEqual(Array.from(result.brands),[]);assert.deepEqual(Array.from(result.formFactors),[]);assert.equal('futureDeviceId' in result,false)
 assert.throws(()=>vm.runInContext('Object.getOwnPropertyDescriptor(N.prototype,"userAgentData").get.call({})',ctx),/receiver/)
 await assert.rejects(vm.runInContext('UA.prototype.getHighEntropyValues.call({},[])',ctx),/receiver/)
})
