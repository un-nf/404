// Operator acceptance requires a real TURN allocation. No credentials are
// embedded, printed or forwarded into the page's profile carrier.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const root=path.resolve(__dirname,'..'),playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright'),engine=process.env.STATIC_BROWSER_ENGINE||'chromium';
const profile=JSON.parse(fs.readFileSync(path.join(root,`profiles/${engine==='firefox'?'firefox':'chrome'}-windows.json`)));
profile.fingerprint.webrtc_transport_policy='relay-only';profile.fingerprint.webrtc_observation_policy='preserve-relay-routing';
const urls=JSON.parse(process.env.STATIC_TURN_URLS||'[]');
if(!Array.isArray(urls)||!urls.length||!process.env.STATIC_TURN_USERNAME||!process.env.STATIC_TURN_PASSWORD)throw Error('Real TURN acceptance requires STATIC_TURN_URLS JSON, STATIC_TURN_USERNAME and STATIC_TURN_PASSWORD');
const iceServers=[{urls,username:process.env.STATIC_TURN_USERNAME,credential:process.env.STATIC_TURN_PASSWORD}],bundle=fs.readFileSync(path.join(root,'assets/js/dist/runtime.bundle.js'));
const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/runtime.js'?'text/javascript':'text/html');res.end(req.url==='/runtime.js'?bundle:`<!doctype html><script src="/runtime.js" data-static-config-b64="${Buffer.from(JSON.stringify(profile)).toString('base64')}"></script>`);});
async function main(){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const browser=await playwright[engine].launch({headless:true});const contexts=[];
 try{const pages=[];for(let i=0;i<2;i++){const context=await browser.newContext();contexts.push(context);const page=await context.newPage();await page.goto(`http://localhost:${server.address().port}/`);await page.evaluate(config=>{window.peer=new RTCPeerConnection(config);window.received=[];peer.ondatachannel=event=>{window.channel=event.channel;channel.onmessage=event=>received.push(event.data);};},{iceServers});pages.push(page);}
  await pages[0].evaluate(()=>{window.channel=peer.createDataChannel('audit');channel.onmessage=event=>received.push(event.data);});
  const gather=async(page,kind)=>page.evaluate(async kind=>{await peer.setLocalDescription(await peer[kind]());if(peer.iceGatheringState!=='complete')await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('TURN gathering timed out')),20000);peer.addEventListener('icegatheringstatechange',()=>{if(peer.iceGatheringState==='complete'){clearTimeout(timer);resolve();}});});return peer.localDescription.toJSON();},kind);
  const offer=await gather(pages[0],'createOffer');await pages[1].evaluate(offer=>peer.setRemoteDescription(offer),offer);const answer=await gather(pages[1],'createAnswer');await pages[0].evaluate(answer=>peer.setRemoteDescription(answer),answer);
  for(const page of pages)await page.waitForFunction(()=>window.channel?.readyState==='open',null,{timeout:30000});
  await pages[0].evaluate(()=>channel.send('A-to-B'));await pages[1].evaluate(()=>channel.send('B-to-A'));
  await pages[0].waitForFunction(()=>received.includes('B-to-A'));await pages[1].waitForFunction(()=>received.includes('A-to-B'));
  for(const description of [offer,answer]){const candidates=description.sdp.split(/\r?\n/).filter(line=>line.startsWith('a=candidate:'));assert.ok(candidates.length,'TURN must provide relay candidates');assert.ok(candidates.every(line=>line.includes(' typ relay')),'No direct route permitted');}
  const results=await Promise.all(pages.map(page=>page.evaluate(async()=>{const report=await peer.getStats();const rows=[...report.values()].filter(row=>row.type==='local-candidate'||row.type==='remote-candidate');return{connected:peer.connectionState==='connected',received:received.length,addressObservations:rows.map(row=>row.address)};})));
  assert.ok(results.every(result=>result.connected&&result.received===1));fs.mkdirSync(path.join(root,'target/audit-contracts'),{recursive:true});fs.writeFileSync(path.join(root,`target/audit-contracts/turn-${engine}.json`),JSON.stringify({engine,version:browser.version(),scope:'two separate browser contexts and real TURN; not two physical machines; relay allocation endpoints intentionally usable',results},null,2)+'\n');
 }finally{for(const context of contexts)await context.close();await browser.close();await new Promise(resolve=>server.close(resolve));}}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
