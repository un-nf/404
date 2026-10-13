// Real installers from both reviewed commits versus the local correction.
// BrowserLeaks currently reports metadata; this independent rendering probe
// follows the public FingerprintJS oscillator/compressor graph, not its SDK.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto')
const {execFileSync}=require('node:child_process'),esbuild=require('../build/node_modules/esbuild')
const playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright')
const root=path.resolve(__dirname,'..'),engine=process.env.STATIC_BROWSER_ENGINE||'chromium'
const profile=JSON.parse(fs.readFileSync(path.join(root,'profiles/chrome-windows.json')))
profile.fingerprint.audio_context={sample_rate:44100,channel_count:1,max_channel_count:6,number_of_inputs:2,number_of_outputs:3,hardware_profiles:[{id:'comparison',sample_rate:44100,render:{gain:1,bias:0,feedback:1.6e-7,modulation:2.2e-8}}]}
async function source(commit){
 const audio=commit?execFileSync('git',['show',`${commit}:src/STATIC_proxy/assets/js/src/spoofing/audio.js`],{cwd:root,encoding:'utf8'}):null
 const built=await esbuild.build({stdin:{contents:`import {initRuntime,getRuntime} from './assets/js/src/core/guard.js';import {loadConfig} from './assets/js/src/core/config.js';import {captureNativeRefs} from './assets/js/src/core/native-refs.js';import {installAudioSpoof} from './assets/js/src/spoofing/audio.js';initRuntime();loadConfig(${JSON.stringify(profile)});captureNativeRefs();getRuntime().entropy={sessionId:'comparison',hash:()=>7,rng:()=>()=>0.5};installAudioSpoof();`,resolveDir:root},bundle:true,format:'iife',write:false,plugins:audio?[{name:'historical-installer',setup(build){build.onLoad({filter:/spoofing[\\/]audio\.js$/},args=>({contents:audio,resolveDir:path.dirname(args.path)}))}}]:[]})
 return built.outputFiles[0].text
}
async function main(){
 const browser=await playwright[engine].launch({headless:true,...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})})
 const report={engine,version:browser.version(),liveBrowserLeaks:process.env.STATIC_BROWSERLEAKS_LIVE==='1',probe:'local oscillator/compressor comparison with optional live BrowserLeaks metadata; not the historical BrowserLeaks version or full FingerprintJS SDK',runs:{}}
 try{
  for(const [label,commit] of [['native',null],['old','10ee191'],['rewrite','459dadc'],['restored',null]]){
   const context=await browser.newContext();if(label!=='native')await context.addInitScript(await source(commit))
   const page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));await page.goto('data:text/html,<html><body>Audio comparison</body></html>')
   report.runs[label]=await page.evaluate(async()=>{
    const context=new OfflineAudioContext(1,5000,44100),osc=context.createOscillator(),compressor=context.createDynamicsCompressor()
    osc.type='triangle';osc.frequency.value=10000;compressor.threshold.value=-50;compressor.knee.value=40;compressor.ratio.value=12;compressor.attack.value=0;compressor.release.value=.25
    osc.connect(compressor);compressor.connect(context.destination);osc.start(0)
    const buffer=await context.startRendering(),frequency=osc.frequency.value,samples=Array.from(buffer.getChannelData(0))
    const ordinary=new OfflineAudioContext(1,8192,44100),tone=ordinary.createOscillator();tone.frequency.value=777
    let conversions=0;tone.start({valueOf(){conversions++;return 0}});const changed=tone.frequency.value
    let repeatError;try{tone.start()}catch(e){repeatError=e.name}
    const afterError=tone.frequency.value;tone.frequency.setValueAtTime(880,.01);tone.connect(ordinary.destination);tone.stop(.1)
    const output=await ordinary.startRendering()
    let invalidReceiver;try{tone.start.call({})}catch(e){invalidReceiver=e.name}
    const live=new AudioContext(),destination=live.destination
    const metadata={sampleRate:live.sampleRate,maxChannelCount:destination.maxChannelCount,channelCount:destination.channelCount,numberOfInputs:destination.numberOfInputs,numberOfOutputs:destination.numberOfOutputs};await live.close()
    return {samples,frequency,metadata,ordinary:{changed,conversions,repeatError,afterError,invalidReceiver,laterAutomation:tone.frequency.value,finite:Array.from(output.getChannelData(0)).every(Number.isFinite)}}
   })
   const row=report.runs[label];row.hash=crypto.createHash('sha256').update(Buffer.from(new Float32Array(row.samples).buffer)).digest('hex');row.sum=row.samples.slice(4500).reduce((a,v)=>a+Math.abs(v),0);delete row.samples
   if(process.env.STATIC_BROWSERLEAKS_LIVE==='1'){
    await page.goto('https://browserleaks.com/javascript',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.getElementById('js-sampleRate')?.textContent.trim())
    row.browserLeaks=await page.evaluate(()=>Object.fromEntries(['sampleRate','maxChannelCount','channelCount','numberOfInputs','numberOfOutputs'].map(key=>[key,document.getElementById('js-'+key)?.textContent])))
   }
   row.installationErrors=errors;assert.deepEqual(errors,[],label+' installation errors');await context.close()
  }
  const {old,rewrite,restored}=report.runs
  console.log(JSON.stringify(report,null,2))
  assert.equal(restored.frequency,old.frequency);assert.notEqual(restored.frequency,rewrite.frequency)
  assert.notEqual(restored.hash,rewrite.hash);assert.equal(restored.hash,old.hash)
  assert.equal(restored.metadata.sampleRate,44100);assert.equal(restored.metadata.maxChannelCount,6);assert.equal(restored.metadata.channelCount,1)
  assert.equal(restored.ordinary.conversions,1);assert.equal(restored.ordinary.repeatError,'InvalidStateError');assert.equal(restored.ordinary.afterError,restored.ordinary.changed)
  assert.equal(restored.ordinary.invalidReceiver,'TypeError');assert.equal(restored.ordinary.laterAutomation,880);assert.equal(restored.ordinary.finite,true)
  fs.mkdirSync(path.join(root,'target/audio-comparison'),{recursive:true});fs.writeFileSync(path.join(root,`target/audio-comparison/${engine}.json`),JSON.stringify(report,null,2)+'\n')
 }finally{await browser.close()}
}
main().catch(error=>{console.error(error);process.exitCode=1})
