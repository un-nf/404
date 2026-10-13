const {test} = require('node:test')
const assert = require('node:assert/strict')
const vm = require('node:vm')
const path = require('node:path')
const esbuild = require('../build/node_modules/esbuild')
const root = path.resolve(__dirname, '..')
const source = esbuild.build({stdin:{contents:`
  export * from './assets/js/src/core/guard.js';
  export * from './assets/js/src/core/config.js';
  export * from './assets/js/src/capabilities/storage.js';
  export * from './assets/js/src/capabilities/permissions.js';
  export * from './assets/js/src/capabilities/media-capabilities.js';
  export * from './assets/js/src/spoofing/speech.js';`,resolveDir:root},
  bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
const profile = (extra={}) => ({fingerprint:{user_agent:'Windows AppleWebKit/537.36 Chrome/147.0.0.0',
  platform:'Win32',vendor:'Google Inc.',browser_variant:'chrome',canvas_hash:'test',
  webgl_vendor:'test',webgl_renderer:'test',languages:['en-US'],...extra}})
async function setup(extra={}) {
  const context=vm.createContext({module:{exports:{}},console:{warn(){},error(){}}})
  vm.runInContext(await source,context)
  const api=context.module.exports
  api.initRuntime();api.loadConfig(profile(extra))
  return {context,api}
}

test('storage masks hardware quota and detailed usage, with coherent mutable fresh dictionaries',async()=>{
  const {api}=await setup()
  const native={quota:987654321987,usage:1500000,usageDetails:{indexedDB:1500000}}
  const masked=api.normalizeStorageEstimate(native,{storage_quota:107374182400})
  assert.equal(masked.quota,107374182400);assert.equal(masked.usage,2097152)
  assert.deepEqual(Object.keys(masked.usageDetails),[])
  masked.quota=1
  assert.equal(api.normalizeStorageEstimate(native,{}).quota,107374182400)
  assert.equal(native.quota,987654321987)
  const large=api.normalizeStorageEstimate({usage:200000000000}, {})
  assert.ok(large.quota>=large.usage)
})

test('media dictionaries mask hardware hints while keeping support and real DRM handles',async()=>{
  const {api}=await setup();const handle={}
  const native={supported:true,smooth:false,powerEfficient:false,keySystemAccess:handle,configuration:{type:'file'}}
  const masked=api.normalizeMediaCapability(native,{})
  assert.equal(masked.smooth,true);assert.equal(masked.powerEfficient,true)
  assert.equal(masked.keySystemAccess,handle);assert.equal(masked.configuration,native.configuration)
  assert.equal(native.smooth,false)
  const unsupported=api.normalizeMediaCapability({supported:false,smooth:false,powerEfficient:false},{})
  assert.equal(unsupported.supported,false);assert.equal(unsupported.smooth,false)
})

test('media wrapper calls native once and retains rejection, receiver and arguments',async()=>{
  const {api,context}=await setup()
  vm.runInContext(`
    calls=0; input={}; failure=new TypeError('native validation');
    class MediaCapabilities { decodingInfo(value) {
      if(!(this instanceof MediaCapabilities)) return Promise.reject(new TypeError('receiver'));
      calls++; if(value!==input) return Promise.reject(failure);
      return Promise.resolve({supported:true,smooth:false,powerEfficient:false});
    }}
    navigator={mediaCapabilities:new MediaCapabilities()};`,context)
  api.installMediaCapabilities()
  const value=await vm.runInContext('navigator.mediaCapabilities.decodingInfo(input)',context)
  assert.equal(value.powerEfficient,true);assert.equal(context.calls,1)
  await assert.rejects(vm.runInContext('navigator.mediaCapabilities.decodingInfo({})',context),e=>e===context.failure)
  await assert.rejects(vm.runInContext('navigator.mediaCapabilities.decodingInfo.call({},input)',context),/receiver/)
})

test('permission policy masks grants, preserves explicit native and persistence observations',async()=>{
  const {api}=await setup()
  assert.equal(api.permissionObservation('camera','granted',{}),'denied')
  assert.equal(api.permissionObservation('notifications','granted',{}),'denied')
  assert.equal(api.permissionObservation('midi','granted',{}),'prompt')
  assert.equal(api.permissionObservation('camera','granted',{permission_states:{camera:'native'}}),'granted')
  assert.equal(api.permissionObservation('persistent-storage','granted',{}),'granted')
})

test('permission objects keep native state brand and convert frozen descriptors once',async()=>{
  const {api,context}=await setup()
  vm.runInContext(`
    const state=new WeakMap();
    class PermissionStatus {constructor(){state.set(this,'granted')} get state(){
      if(!state.has(this)) throw new TypeError('receiver');return state.get(this)}}
    class Permissions {query(descriptor){if(!(this instanceof Permissions)) return Promise.reject(new TypeError('receiver'));
      const name=String(descriptor.name);if(name!=='camera') return Promise.reject(new TypeError('invalid'));
      return Promise.resolve(new PermissionStatus())}}
    globalThis.PermissionStatus=PermissionStatus;
    navigator={permissions:new Permissions()};
    reads=0;conversions=0;input=Object.freeze({get name(){if(this!==input)throw new Error('receiver');reads++;
      return {toString(){conversions++;return 'camera'}}}});`,context)
  api.installPermissions()
  assert.equal(await vm.runInContext('navigator.permissions.query(input).then(s=>s.state)',context),'denied')
  assert.equal(context.reads,1);assert.equal(context.conversions,1)
  assert.throws(()=>vm.runInContext("Object.getOwnPropertyDescriptor(PermissionStatus.prototype,'state').get.call({})",context),/receiver/)
  assert.throws(()=>vm.runInContext('navigator.permissions.query({name:Symbol()})',context),/Symbol/)
})

test('speech masks a populated installed inventory without fabricating unusable voices',async()=>{
  const {api,context}=await setup()
  vm.runInContext(`
    const records=new WeakMap();
    class SpeechSynthesisVoice {constructor(name,lang,local=true){records.set(this,{name,voiceURI:name,lang,localService:local,default:false})}}
    for(const key of ['name','voiceURI','lang','localService','default'])Object.defineProperty(SpeechSynthesisVoice.prototype,key,
      {configurable:true,enumerable:true,get(){if(!records.has(this))throw new TypeError('receiver');return records.get(this)[key]}});
    globalThis.SpeechSynthesisVoice=SpeechSynthesisVoice;
    voices=[new SpeechSynthesisVoice('Installed A','en-US'),new SpeechSynthesisVoice('Installed B','en-US'),
      new SpeechSynthesisVoice('Installed C','en-US'),new SpeechSynthesisVoice('Installed French','fr-FR'),
      new SpeechSynthesisVoice('Remote English','en-US',false)];
    class SpeechSynthesis {getVoices(){if(!(this instanceof SpeechSynthesis))throw new TypeError('receiver');return voices.slice()}}
    speechSynthesis=new SpeechSynthesis();`,context)
  api.installSpeechSpoof()
  const result=vm.runInContext('speechSynthesis.getVoices()',context)
  assert.equal(result.length,2);assert.equal(result[0],context.voices[0])
  assert.equal(result[0].name,'en-US Voice 1');assert.equal(result[0].voiceURI,'urn:voice:en-US:1')
  assert.equal(result[0].default,true);assert.equal(result[1].default,false)
  result.pop();assert.equal(vm.runInContext('speechSynthesis.getVoices().length',context),2)
  assert.throws(()=>vm.runInContext('speechSynthesis.getVoices.call({})',context),/receiver/)
  assert.throws(()=>vm.runInContext("Object.getOwnPropertyDescriptor(SpeechSynthesisVoice.prototype,'name').get.call({})",context),/receiver/)
  vm.runInContext('voices=[]',context);assert.equal(vm.runInContext('speechSynthesis.getVoices().length',context),0)
})

test('privacy profile fields reject unsafe or contradictory inputs before installation',async()=>{
  for(const extra of [{storage_usage_quantum:0},{storage_quota:NaN},{storage_usage:20,storage_quota:10},
    {speech_voice_limit:-1},{speech_languages:[]},{media_devices_per_kind:0},{cookie_enabled:'yes'},{save_data:1},{permission_states:{camera:'granted'}},
    {permission_states:{notifications:'prompt'}},{media_capabilities:{smooth:'yes'}}]) {
    await assert.rejects(setup(extra),/STATIC/)
  }
})
