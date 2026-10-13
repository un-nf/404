const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),fs=require('node:fs')
const esbuild=require('../build/node_modules/esbuild'),root=path.resolve(__dirname,'..')
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/schema.js';export * from './assets/js/src/core/guard.js';export * from './assets/js/src/core/config.js';export * from './assets/js/src/core/policy.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
async function api(){const ctx=vm.createContext({module:{exports:{}},location:{hostname:'google.com'}});vm.runInContext(await source,ctx);ctx.module.exports.initRuntime();return ctx.module.exports}
const profile=()=>JSON.parse(fs.readFileSync(path.join(root,'profiles/chrome-windows.json'))).fingerprint
test('shared schema rejects typos, contradictory aliases and invalid nested numeric controls',async()=>{
 const a=await api(),p=profile();p.enable_unknown_spoof=true;assert.throws(()=>a.normalizeFingerprint(p),/unknown field/)
 const q=profile();q.enable_font_spoof=true;q.enable_font_metric_spoof=false;assert.throws(()=>a.normalizeFingerprint(q),/conflicting/)
 const r=profile();r.canvas_noise={noise_probability:2};assert.throws(()=>a.normalizeFingerprint(r),/range/)
 assert.throws(()=>a.loadConfig({fingerprint:profile(),privacy_rules:[{pathPrefix:'/all'}]}),/invalid rule/)
 assert.throws(()=>a.loadConfig({fingerprint:profile(),privacy_rules:[{hostSuffix:'example.com',pathPrefix:'relative'}]}),/invalid rule/)
})
test('canonical flags control observations and hostname exception mode is rejected',async()=>{
 const a=await api(),p=profile();p.enable_font_spoof=false;delete p.enable_font_metric_spoof
 for(const key of ['enable_permissions_spoof','enable_notifications_spoof','enable_battery_spoof','enable_media_capabilities_spoof','enable_privacy_blackhole'])p[key]=false
 a.loadConfig({fingerprint:p});a.initPolicy();const policy=a.getPolicy()
 for(const key of ['fontMetricsEnabled','permissionsEnabled','notificationsEnabled','batteryEnabled','mediaCapabilitiesEnabled','privacyBlackholeEnabled'])assert.equal(policy[key],false,key)
 assert.equal(policy.stabilityMode,undefined);assert.equal(policy.audioEnabled,true);assert.equal(policy.eventTimingEnabled,true)
 const b=await api(),q=profile();q.compatibility_mode='legacy-host-exceptions'
 assert.throws(()=>b.loadConfig({fingerprint:q}),/STATIC/)
})
test('deprecated metadata is reported and persona snapshots including defaults are frozen',async()=>{
 const a=await api(),p=profile();p.fonts=['Arial'];const report=a.normalizeFingerprint(p)
 assert.ok(report.unsupported.includes('fonts'));assert.equal(p.compatibility_mode,undefined)
 a.loadConfig({fingerprint:p});assert.equal(Object.isFrozen(a.getFingerprint()),true)
 assert.equal(Object.isFrozen(a.getFingerprint().fonts),true)
})

test('shared valid/invalid fixtures agree before installation',async()=>{
 const cases=require('./fixtures/profile-validation.json')
 for(const item of cases){const a=await api();let accepted=true;try{a.loadConfig({fingerprint:{...profile(),...item.patch}})}catch{accepted=false}assert.equal(accepted,item.valid,item.id)}
})
