// Real Chromium UA-CH: no native method stand-in or CDP identity override.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..');
const pw=require(process.env.STATIC_PLAYWRIGHT_MODULE||'../build/node_modules/playwright');
const profile=JSON.parse(fs.readFileSync(path.join(root,'profiles/chrome-windows.json')));
const dist=path.join(root,'assets/js/dist');
const bundles=Object.fromEntries(['runtime','worker-classic','worker-module'].map(name=>[name,fs.readFileSync(path.join(dist,name+'.bundle.js'),'utf8')]));
async function probe(expected){
 const previous=Object.getOwnPropertyDescriptor(Object.prototype,'then'),observed=[];
 let value;
 try{
  Object.defineProperty(Object.prototype,'then',{configurable:true,get(){
   if(Object.hasOwn(this,'architecture'))observed.push(this.architecture);
   return undefined;
  }});
  value=await navigator.userAgentData.getHighEntropyValues(['architecture','bitness','fullVersionList','wow64','formFactors']);
 }finally{if(previous)Object.defineProperty(Object.prototype,'then',previous);else delete Object.prototype.then;}
 return {observed,value,expected,prototypeRestored:previous?Object.getOwnPropertyDescriptor(Object.prototype,'then').get===previous.get:!Object.hasOwn(Object.prototype,'then')};
}
async function contracts(){
 const ua=navigator.userAgentData,fn=ua.getHighEntropyValues,outcomes=[];
 for(const [name,receiver,args]of [['missing',ua,[]],['undefined',ua,[undefined]],['null',ua,[null]],['string',ua,['architecture']],['number',ua,[1]],['arraylike',ua,[{0:'architecture',length:1}]],['symbol',ua,[[Symbol()]]],['invalid receiver',{},[[]]],['null receiver',null,[[]]],['empty',ua,[[]]],['unknown',ua,[['future']]],['object',ua,[[{toString(){return 'architecture'}}]]]]){
  let promise;try{promise=Reflect.apply(fn,receiver,args)}catch(e){outcomes.push({name,phase:'throw',error:e.name});continue;}
  try{outcomes.push({name,phase:'resolve',keys:Object.keys(await promise)})}catch(e){outcomes.push({name,phase:'reject',error:e.name})}
 }
 const conversion=[];let returns=0;
 const iterable={get [Symbol.iterator](){conversion.push('iterator');return function(){conversion.push('call');let index=0;return{get next(){conversion.push('next');return function(){conversion.push('step');if(index++)return{done:true};return{get done(){conversion.push('done');return false},get value(){conversion.push('value');return{[Symbol.toPrimitive](hint){conversion.push(hint);throw failure}}}}}},return(){returns++;return{done:true}}}}}};
 const failure={sentinel:true};let sameError=false;
 try{await fn.call(ua,iterable)}catch(e){sameError=e===failure}
 return{outcomes,conversion,returns,sameError,name:fn.name,length:fn.length};
}
let expected,server;
async function main(){
 server=http.createServer((req,res)=>{
  if(req.url==='/runtime.js'){res.setHeader('Content-Type','text/javascript');return res.end(bundles.runtime)}
  if(req.url.startsWith('/worker-runtime.mjs?')){res.setHeader('Content-Type','text/javascript');return res.end(bundles['worker-module'])}
  if(req.url==='/classic.js'||req.url==='/module.js'){
   res.setHeader('Content-Type','text/javascript');
   const baseline="await navigator.userAgentData.getHighEntropyValues(['architecture'])";
   const tail=`const report=await (${probe.toString()})(${JSON.stringify(expected)});postMessage({baseline,...report});`;
   if(req.url==='/module.js')return res.end(`const baseline=${baseline};await import('/worker-runtime.mjs?profile=${Buffer.from(JSON.stringify(profile.fingerprint)).toString('base64url')}');${tail}`);
   return res.end(`(async()=>{const baseline=${baseline};${bundles['worker-classic']}(${JSON.stringify(profile.fingerprint)});${tail}})().catch(error=>postMessage({error:String(error)}));`);
  }
  res.setHeader('Content-Type','text/html');
  res.end('<!doctype html><title>UA-CH regression</title>'+ (req.url==='/protected'?`<script src="/runtime.js" data-static-config-b64="${Buffer.from(JSON.stringify(profile)).toString('base64')}"></script>`:''));
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try{
  browser=await pw.chromium.launch({headless:true,...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})});
  const page=await browser.newPage(),origin='http://localhost:'+server.address().port;
  await page.goto(origin+'/baseline');
  const baseline=await page.evaluate(()=>navigator.userAgentData.getHighEntropyValues(['architecture']));
  assert.ok(baseline.architecture,'the real browser must provide a baseline architecture');
  expected=profile.fingerprint.ua_data.architecture=baseline.architecture==='arm'?'x86':'arm';
  const nativeProbe=await page.evaluate(probe,expected),nativeContracts=await page.evaluate(contracts);
  await page.goto(origin+'/protected');
  const patched=await page.evaluate(probe,expected),patchedContracts=await page.evaluate(contracts);
  const frame=await page.evaluate(async expected=>{
   const frame=document.createElement('iframe');document.body.append(frame);
   try{return await frame.contentWindow.eval('('+String(expected.probe)+')') (expected.architecture)}finally{frame.remove()}
  },{probe:probe.toString(),architecture:expected});
  const workers={};
  for(const type of ['classic','module'])workers[type]=await page.evaluate(type=>new Promise((resolve,reject)=>{
   const worker=new Worker('/'+type+'.js',{type});
   const timeout=setTimeout(()=>{worker.terminate();reject(Error('Worker timeout'))},15000);
   worker.onmessage=e=>{clearTimeout(timeout);worker.terminate();resolve(e.data)};
   worker.onerror=e=>{clearTimeout(timeout);worker.terminate();reject(Error(e.message))};
  }),type);
  const report={browser:browser.version(),executable:process.env.STATIC_BROWSER_EXECUTABLE||'Playwright Chromium',platform:process.platform,baseline,expected,nativeProbe,nativeContracts,patched,patchedContracts,frame,workers,bundles:Object.fromEntries(Object.entries(bundles).map(([name,value])=>[name,crypto.createHash('sha256').update(value).digest('hex')])),scope:'Generated bundles in local HTTP window, reachable child, classic/module worker. No full proxy or pre-bootstrap guarantee.'};
  fs.mkdirSync(path.join(root,'target/audit-contracts'),{recursive:true});
  fs.writeFileSync(path.join(root,`target/audit-contracts/uach-isolation-${process.env.STATIC_UACH_LABEL||'current'}.json`),JSON.stringify(report,null,2)+'\n');
  assert.notEqual(expected,baseline.architecture);
  for(const [name,result]of Object.entries({window:patched,frame,...workers})){
   assert.equal(result.error,undefined,name);
   assert.equal(result.value.architecture,expected,name);
   assert.ok(result.observed.length>0,name+': getter actually ran');
   assert.ok(result.observed.every(x=>x===expected),name+': no baseline architecture observation');
   assert.equal(result.prototypeRestored,true,name+': descriptor cleanup');
  }
  assert.deepEqual(patchedContracts,nativeContracts,'native conversion order, receiver rejection, dictionary key order and method shape');
  console.log(JSON.stringify({browser:browser.version(),baseline:baseline.architecture,profile:expected,nativeObserved:nativeProbe.observed,protectedObserved:patched.observed,realms:['window','frame','classic worker','module worker'],passed:true},null,2));
 }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
}
main().catch(e=>{console.error(e);process.exitCode=1});
