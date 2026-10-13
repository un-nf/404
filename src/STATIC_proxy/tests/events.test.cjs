const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..')
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/events.js';export * from './assets/js/src/core/patches.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
test('fixed-observation event bridge preserves application events, suppresses trusted transitions and rolls back registrations',async()=>{
 const ctx=vm.createContext({module:{exports:{}}})
 vm.runInContext(`class E {constructor(trusted){this.isTrusted=trusted;this.stopped=false}stopImmediatePropagation(){this.stopped=true}}
  class T {constructor(){this.listeners=[]}addEventListener(type,listener,capture){this.listeners.push({type,listener,capture})}removeEventListener(type,listener){this.listeners=this.listeners.filter(x=>x.listener!==listener)}fire(trusted){const event=new E(trusted);for(const x of this.listeners){x.listener(event);if(event.stopped)break}}}
  globalThis.Event=E;globalThis.EventTarget=T;target=new T();calls=0;`,ctx)
 vm.runInContext(await source,ctx);const api=ctx.module.exports
 api.suppressNativeTransitions(ctx.target,['change']);api.suppressNativeTransitions(ctx.target,['change'])
 vm.runInContext(`target.addEventListener('change',()=>calls++);target.fire(true);target.fire(false)`,ctx)
 assert.equal(ctx.calls,1);assert.equal(ctx.target.listeners.length,2)
 const other=vm.runInContext('new T()',ctx)
 assert.throws(()=>api.transaction(()=>{api.suppressNativeTransitions(other,['change']);throw Error('rollback')}),/rollback/)
 assert.equal(other.listeners.length,0)
})
