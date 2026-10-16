const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),vm=require('node:vm'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..')
test('explicit audio metadata overrides built-in and resolved hardware defaults',async()=>{
 const build=await esbuild.build({stdin:{contents:`export {resolveAudioPersona} from './assets/js/src/spoofing/audio.js';`,resolveDir:root},bundle:true,format:'cjs',write:false})
 const ctx=vm.createContext({module:{exports:{}}});vm.runInContext(build.outputFiles[0].text,ctx)
 const runtime={entropy:{sessionId:'test',hash:()=>7,rng:()=>()=>0.5}}
 const value=ctx.module.exports.resolveAudioPersona(runtime,{audio_context:{sample_rate:44100,channel_count:1,max_channel_count:6,number_of_inputs:2,number_of_outputs:3,hardware_profiles:[{sample_rate:48000,channel_count:2,max_channel_count:2,number_of_inputs:1,number_of_outputs:0}]}})
 assert.equal(value.sampleRate,44100);assert.equal(value.channelCount,1);assert.equal(value.maxChannelCount,6);assert.equal(value.numberOfInputs,2);assert.equal(value.numberOfOutputs,3)
 assert.equal(ctx.module.exports.resolveAudioPersona(runtime,{audio_context:{sample_rate:44100}}).sampleRate,44100)
})
