const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..'),core=path.join(root,'assets/js/src/core').replaceAll('\\','/')
test('complete Window startup retries failed modules without recapturing wrappers or replacing configuration/entropy',async()=>{
 const result=await esbuild.build({stdin:{contents:`export * from './assets/js/src/runtime.js';export * from './assets/js/src/core/guard.js';`,resolveDir:root},bundle:true,format:'cjs',write:false,plugins:[{name:'controlled-surfaces',setup(build){build.onLoad({filter:/assets[\\/]js[\\/]src[\\/]/},args=>{
  const name=path.basename(args.path),folder=path.basename(path.dirname(args.path)),imports=`import {getRuntime,markModule} from '${core}/guard.js';import {definePatch} from '${core}/patches.js';`
  const setup={
   'config.js':`export function loadConfig(raw){counts.config++;getRuntime().config=Object.freeze({ready:true,fingerprint:Object.freeze({...raw.fingerprint}),contract:{unsupported:[]}})}export function getFingerprint(){return getRuntime().config.fingerprint}`,
   'native-refs.js':`export function captureNativeRefs(){counts.refs++;getRuntime().nativeRefs=Object.freeze({functionToString:Function.prototype.toString,original:target.fn})}`,
   'nonce.js':`export function captureNonce(){counts.nonce++;getRuntime().nonce='nonce'}`,
   'entropy.js':`export function initEntropy(){counts.entropy++;getRuntime().entropy=Object.freeze({generation:counts.entropy})}`,
   'toString.js':`export function installToStringProxy(){counts.toString++;definePatch(target,'marker',{value:1,configurable:true});markModule('toString')}`
  }
  if(folder==='core'&&setup[name])return {contents:imports+setup[name],resolveDir:path.dirname(args.path)}
  if(!['identity','capabilities','spoofing','evasion','privacy','contexts'].includes(folder))return
  const names=[...fs.readFileSync(args.path,'utf8').matchAll(/export function (\w+)/g)].map(m=>m[1])
  return {contents:imports+names.map(fn=>`export function ${fn}(){${name==='navigator.js'?`counts.navigator++;definePatch(target,'fn',{value:function(){return getRuntime().nativeRefs.original()+1},writable:true,configurable:true});markModule('navigator')`:name==='network.js'?`counts.network++;definePatch(target,'temporary',{value:1,configurable:true});if(fail)throw Error('partial fault');markModule('network')`:''}}`).join('\n'),resolveDir:path.dirname(args.path)}
 })}}]})
 const counts={config:0,refs:0,nonce:0,entropy:0,toString:0,navigator:0,network:0},original=()=>42
 const ctx=vm.createContext({module:{exports:{}},counts,target:{fn:original},fail:true,location:{hostname:'fixture.test'},console:{error(){}}})
 vm.runInContext(result.outputFiles[0].text,ctx);const api=ctx.module.exports
 assert.equal(api.startRuntime({fingerprint:{user_agent:'selected'}}), 'failed')
 const before=api.getRuntime(),config=before.config,entropy=before.entropy,refs=before.nativeRefs
 assert.equal(ctx.target.fn(),43);assert.equal('temporary' in ctx.target,false)
 ctx.fail=false;assert.equal(api.startRuntime({fingerprint:{user_agent:'must not replace'}}),'ready')
 assert.equal(api.getRuntime().config,config);assert.equal(api.getRuntime().entropy,entropy);assert.equal(api.getRuntime().nativeRefs,refs);assert.equal(refs.original,original)
 assert.equal(ctx.target.fn(),43);assert.deepEqual(counts,{config:1,refs:1,nonce:1,entropy:1,toString:1,navigator:1,network:2})
})
