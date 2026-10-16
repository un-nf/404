const {test}=require('node:test');
const assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path');
const esbuild=require('../build/node_modules/esbuild'),root=path.resolve(__dirname,'..');
const profile=require('../profiles/chrome-windows.json');
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/guard.js';export * from './assets/js/src/core/config.js';export * from './assets/js/src/identity/navigator.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text);
async function setup(){
 const context=vm.createContext({module:{exports:{}}});
 vm.runInContext(await source,context);
 const api=context.module.exports;api.initRuntime();api.loadConfig(profile);
 vm.runInContext(`
 const receivers=new WeakSet();nativeCalls=0;
 class UA {
  constructor(){receivers.add(this)}
  get brands(){if(!receivers.has(this))throw TypeError('Illegal invocation');return [{brand:'host',version:'999'}]}
  get mobile(){if(!receivers.has(this))throw TypeError('Illegal invocation');return true}
  get platform(){if(!receivers.has(this))throw TypeError('Illegal invocation');return 'host-OS'}
  getHighEntropyValues(){nativeCalls++;return Promise.resolve({architecture:'host-arm64',bitness:'64',brands:[],mobile:false,platform:'host-OS'})}
  toJSON(){return {brands:this.brands,mobile:true,platform:'host-OS'}}
 }
 class Navigator {get userAgentData(){return ua}}
 ua=new UA();navigator=new Navigator();
 `,context);
 api.installNavigator();return{context,api};
}
test('UA-CH never acquires a host dictionary before inherited then normalization',async()=>{
 const {context}=await setup();
 const report=await vm.runInContext(`(async()=>{
  const observed=[],previous=Object.getOwnPropertyDescriptor(Object.prototype,'then');
  try{
   Object.defineProperty(Object.prototype,'then',{configurable:true,get(){if(Object.hasOwn(this,'architecture'))observed.push(this.architecture);return undefined}});
   const result=await ua.getHighEntropyValues(['architecture']);
   return {observed,result,calls:nativeCalls};
  }finally{if(previous)Object.defineProperty(Object.prototype,'then',previous);else delete Object.prototype.then}
 })()`,context);
 assert.equal(report.result.architecture,profile.fingerprint.ua_data.architecture);
 assert.equal(report.observed.includes('host-arm64'),false);
 assert.ok(report.observed.length>0,'the hook must actually observe a resolved dictionary');
 assert.equal(report.calls,0,'native high-entropy acquisition must not run');
 assert.equal(vm.runInContext('Object.hasOwn(Object.prototype,"then")',context),false);
});
test('UA-CH conversion errors reject, preserve thrown objects and never acquire host data',async()=>{
 const {context}=await setup();
 const result=await vm.runInContext(`(async()=>{
  const outcomes=[];
  for(const args of [[],[undefined],[null],['architecture'],[1],[{0:'architecture',length:1}],[[Symbol()]]]){
   let p;try{p=Reflect.apply(UA.prototype.getHighEntropyValues,ua,args)}catch(e){outcomes.push('throw:'+e.name);continue}
   try{await p;outcomes.push('resolved')}catch(e){outcomes.push('reject:'+e.name)}
  }
  let invalid;try{await UA.prototype.getHighEntropyValues.call({},[]);invalid='resolved'}catch(e){invalid=e.name}
  const failure={tag:'page iterator failure'},input={[Symbol.iterator](){throw failure}};
  let preserved=false;try{await ua.getHighEntropyValues(input)}catch(e){preserved=e===failure}
  let reads=0,converted=0;const key={toString(){converted++;return 'architecture'}};
  const iterable={[Symbol.iterator](){reads++;return [key,'unknown','architecture'][Symbol.iterator]()}};
  const value=await ua.getHighEntropyValues(iterable);
  return {outcomes,invalid,preserved,reads,converted,value,calls:nativeCalls};
 })()`,context);
 assert.deepEqual(Array.from(result.outcomes),Array(7).fill('reject:TypeError'));
 assert.equal(result.invalid,'TypeError');assert.equal(result.preserved,true);
 assert.equal(result.reads,1);assert.equal(result.converted,1);assert.equal(result.calls,0);
 assert.deepEqual(Object.keys(result.value),['architecture','brands','mobile','platform']);
});
test('UA-CH output copies cannot mutate the profile and unknown inherited hint names stay absent',async()=>{
 const {context}=await setup();
 const first=await vm.runInContext(`ua.getHighEntropyValues(['formFactors','fullVersionList','toString','then','__proto__'])`,context);
 assert.equal(Object.hasOwn(first,'toString'),false);assert.equal(Object.hasOwn(first,'then'),false);
 first.formFactors[0]='attacker';first.fullVersionList[0].brand='attacker';
 const second=await vm.runInContext(`ua.getHighEntropyValues(['formFactors','fullVersionList'])`,context);
 assert.equal(second.formFactors[0],profile.fingerprint.ua_data.form_factors[0]);
 assert.equal(second.fullVersionList[0].brand,profile.fingerprint.ua_data.full_version_list[0].brand);
});
