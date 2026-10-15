// Genuine graph/descriptor-owner regression. Saved native handles are confined
// to this privileged fixture and never added to the production bundle.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright'),root=path.resolve(__dirname,'..');
const engine=process.env.STATIC_BROWSER_ENGINE||'chromium',profile=require(`../profiles/${engine==='firefox'?'firefox':'chrome'}-windows.json`);
const bundle=fs.readFileSync(path.join(root,'assets/js/dist/runtime.bundle.js'));
const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/runtime.js'?'text/javascript':'text/html');res.end(req.url==='/runtime.js'?bundle:`<!doctype html><script>window.graphNative=Object.fromEntries(['channelCount','numberOfInputs','numberOfOutputs'].map(key=>[key,Object.getOwnPropertyDescriptor(AudioNode.prototype,key).get]));</script><script src="/runtime.js" data-static-config-b64="${Buffer.from(JSON.stringify(profile)).toString('base64')}"></script>`);});
async function main(){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const browser=await playwright[engine].launch({headless:true,...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})});
 try{const page=await browser.newPage();await page.goto(`http://localhost:${server.address().port}/`);
  const result=await page.evaluate(async()=>{
   const live=new AudioContext(),offline=new OfflineAudioContext(1,8192,44100),rows=[];
   for(const context of [live,offline]){
    const nodes=[context.createOscillator(),context.createGain(),context.createDynamicsCompressor(),context.createAnalyser(),context.createChannelMerger(2),context.createChannelSplitter(2)];
    for(const node of nodes)for(const key of Object.keys(graphNative)){const expected=graphNative[key].call(node),actual=node[key];rows.push({node:node.constructor.name,key,expected,actual});}
    const gain=nodes[1];gain.channelCount=1;rows.push({node:'gain setter',key:'channelCount',expected:1,actual:gain.channelCount});
    nodes[0].frequency.value=0;nodes[0].connect(nodes[1]);nodes[1].connect(context.destination);nodes[0].start(0);
    rows.push({node:'zero oscillator',key:'frequency',actual:nodes[0].frequency.value,expectedBelow:1});
    nodes[0].frequency.setValueAtTime(777,.01);nodes[0].stop(.04);
   }
   let eventBuffer;offline.oncomplete=event=>eventBuffer=event.renderedBuffer;const buffer=await offline.startRendering();await new Promise(resolve=>setTimeout(resolve,20));
   const samples=Array.from(buffer.getChannelData(0)),destination={channelCount:live.destination.channelCount,maxChannelCount:live.destination.maxChannelCount,numberOfInputs:live.destination.numberOfInputs,numberOfOutputs:live.destination.numberOfOutputs};
   let invalid;try{Object.getOwnPropertyDescriptor(AudioNode.prototype,'numberOfInputs').get.call({});}catch(error){invalid=error.name;}
   await live.close();return{rows,destination,invalid,finite:samples.every(Number.isFinite),eventSame:eventBuffer===buffer,hasSignal:samples.some(value=>Math.abs(value)>1e-6)};
  });
  for(const row of result.rows)if(row.expectedBelow!==undefined)assert.ok(Math.abs(row.actual)<row.expectedBelow);else assert.equal(row.actual,row.expected,JSON.stringify(row));
  assert.equal(result.invalid,'TypeError');assert.equal(result.eventSame,true);assert.equal(result.finite,true);assert.equal(result.hasSignal,true);
  const fp=profile.fingerprint.audio_context;for(const [key,source]of [['channelCount','channel_count'],['maxChannelCount','max_channel_count'],['numberOfInputs','number_of_inputs'],['numberOfOutputs','number_of_outputs']])assert.equal(result.destination[key],fp[source]);
  fs.mkdirSync(path.join(root,'target/audit-contracts'),{recursive:true});fs.writeFileSync(path.join(root,`target/audit-contracts/audio-${engine}.json`),JSON.stringify({engine,version:browser.version(),bundleSHA256:crypto.createHash('sha256').update(bundle).digest('hex'),profile:profile.fingerprint.browser_variant,scope:'one genuine browser graph; not Seth historical probe or cross-host engine parity',result},null,2)+'\n');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}}
main().catch(error=>{console.error(error);process.exitCode=1;});
