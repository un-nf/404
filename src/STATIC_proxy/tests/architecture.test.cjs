const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..'),profile=require('../profiles/chrome-windows.json')
test('R08 legacy local date policy normalizes or explicitly denies without silent host timezone fallback',async()=>{
 const {api}=await context(['identity/date-model']);
 const model=api.createDateModel('America/New_York',Intl.DateTimeFormat);
 assert.equal(new Date(model.localParse('January 1, 2026 07:00:00')).toISOString(),'2026-01-01T12:00:00.000Z');
 assert.equal(new Date(model.localParse('2026-01-01T07:00:00')).toISOString(),'2026-01-01T12:00:00.000Z');
 assert.equal(model.localParse('2026-01-01'),Date.parse('2026-01-01'));
 assert.equal(model.localParse('January 1, 2026 07:00:00 GMT'),Date.parse('January 1, 2026 07:00:00 GMT'));
 assert.throws(()=>api.createDateModel('America/New_York',Intl.DateTimeFormat,'deny').localParse('January 1, 2026 07:00:00'),/cannot be normalized/);
 assert.ok(Number.isNaN(model.localParse('invalid-date')));
})
async function context(modules,extra={}) {
 const built=await esbuild.build({stdin:{contents:modules.map(name=>`export * from './assets/js/src/${name}.js';`).join('\n'),resolveDir:root},bundle:true,format:'cjs',write:false})
 const ctx=vm.createContext({module:{exports:{}},DOMException,URL,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto,...extra});if(extra.bootstrap)vm.runInContext(extra.bootstrap,ctx);vm.runInContext(built.outputFiles[0].text,ctx)
 const api=ctx.module.exports;if(api.initRuntime){api.initRuntime();api.loadConfig?.(JSON.parse(JSON.stringify(profile)))}return {ctx,api}
}
test('R01 poisoned intrinsics do not receive private native getters and private collections still work',async()=>{
 const {ctx}=await context(['core/descriptors','core/primordials'])
 vm.runInContext(`
 const savedApply=Reflect.apply,savedDescriptor=Object.getOwnPropertyDescriptor;
 const host={};const original=function(){if(this!==host)throw TypeError('receiver');return 64};
 Object.defineProperty(host,'cpu',{get:original,configurable:true});module.exports.replaceGetter(host,'cpu',()=>8);
 const hooks=[];const poison=fn=>function(...args){for(const value of args)if(value===original)hooks.push(value);return savedApply(fn,this,args)};
 Reflect.apply=poison(Reflect.apply);Object.getOwnPropertyDescriptor=poison(Object.getOwnPropertyDescriptor);Object.getPrototypeOf=poison(Object.getPrototypeOf);
 WeakMap.prototype.get=poison(WeakMap.prototype.get);WeakMap.prototype.set=poison(WeakMap.prototype.set);
 Map.prototype.get=poison(Map.prototype.get);Map.prototype.set=poison(Map.prototype.set);
 Function.prototype.call=poison(Function.prototype.call);Function.prototype.apply=poison(Function.prototype.apply);
 Array.prototype.map=poison(Array.prototype.map);Promise.prototype.then=poison(Promise.prototype.then);
 result={masked:host.cpu,leaks:hooks.length};`,ctx)
 assert.equal(ctx.result.masked,8);assert.equal(ctx.result.leaks,0)
})
test('R02 destination metadata does not change inherited oscillator/gain topology or setters',async()=>{
 const {ctx,api}=await context(['core/guard','core/config','spoofing/audio'])
 vm.runInContext(`window=globalThis;class Node {constructor(inputs,outputs){this.i=inputs;this.o=outputs;this.c=2}get channelCount(){if(!(this instanceof Node))throw TypeError('receiver');return this.c}set channelCount(v){this.c=v}get numberOfInputs(){return this.i}get numberOfOutputs(){return this.o}}
 class Destination extends Node {constructor(){super(1,0)}get maxChannelCount(){if(!(this instanceof Destination))throw TypeError('destination');return 64}}
 globalThis.AudioDestinationNode=Destination;d=new Destination();osc=new Node(0,1);gain=new Node(1,1);`,ctx)
 api.getRuntime().nativeRefs={audioDestinationPrototype:ctx.AudioDestinationNode.prototype};api.getRuntime().entropy={origin:'test',sessionId:'test',hash:()=>7,rng:()=>()=>0.5};api.installAudioSpoof()
 const result=vm.runInContext(`osc.channelCount=4;({dest:[d.numberOfInputs,d.numberOfOutputs],osc:[osc.numberOfInputs,osc.numberOfOutputs,osc.channelCount],gain:[gain.numberOfInputs,gain.numberOfOutputs]})`,ctx)
 assert.deepEqual(Array.from(result.dest),[1,0]);assert.deepEqual(Array.from(result.osc),[0,1,4]);assert.deepEqual(Array.from(result.gain),[1,1])
})
test('R03/R04 translations are peer/type/generation scoped, bounded and disposed on close',async()=>{
 const {api}=await context(['core/translations']);const store=api.createTranslationStore(2,4096),a={},b={};
 store.record(a,0,{},'offer','masked','native-A');store.record(b,0,{},'offer','masked','native-B');
 assert.equal(store.reverse(a,{},'offer','masked'),'native-A');assert.equal(store.reverse(b,{},'offer','masked'),'native-B');assert.equal(store.reverse(a,{},'answer','masked'),'masked')
 assert.throws(()=>store.record(a,0,{},'offer','masked','collision'),/Ambiguous/)
 const owned={};store.record(a,0,owned,'offer','masked','native-A');assert.throws(()=>store.reverse(b,owned,'offer','masked'),/another connection/);
 store.reset(a);assert.throws(()=>store.record(a,0,{},'offer','later','expired'),/expired/)
 assert.throws(()=>store.reverse(a,owned,'offer','masked'),/expired/);
 store.reset(b,true);for(let i=0;i<2000;i++){const p={};store.record(p,0,{},'offer','m'+i,'native'+i);store.reset(p,true)}
 assert.deepEqual({...store.counters()},{entries:0,bytes:0})
 const c={};store.record(c,0,{},'offer','1','1');store.record(c,0,{},'offer','2','2');assert.throws(()=>store.record(c,0,{},'offer','3','3'),/budget/)
})
test('R08/R09 frozen Intl options and Date local fields agree with profile timezone',async()=>{
 const {ctx,api}=await context(['core/guard','core/config','identity/timezone']);api.getRuntime().nativeRefs={intlDateTimeFormat:vm.runInContext('Intl.DateTimeFormat',ctx)};api.installTimezone()
 const result=vm.runInContext(`(()=>{const d=new Date('2026-01-01T12:00:00Z');const options=Object.freeze({timeZone:undefined,hour:'2-digit',hourCycle:'h23'});return {hour:d.getHours(),offset:d.getTimezoneOffset(),intl:new Intl.DateTimeFormat('en-US',options).format(d),explicit:new Intl.DateTimeFormat('en-US',{timeZone:'UTC',hour:'2-digit',hourCycle:'h23'}).format(d),constructed:new Date(2026,0,1,7).toISOString(),utc:d.getUTCHours()}})()`,ctx)
 // Chrome profile currently selects America/New_York.
 const zone=profile.fingerprint.timezone;const expected=new Intl.DateTimeFormat('en-US',{timeZone:zone,hour:'2-digit',hourCycle:'h23'}).format(new Date('2026-01-01T12:00:00Z'))
 assert.equal(result.intl,expected);assert.equal(result.hour,Number(expected));assert.equal(result.explicit,'12');assert.equal(result.utc,12)
})
test('R13 malformed GPU limits and incoherent screen/platform profiles reject before installation',async()=>{
 const {api}=await context(['core/guard','core/config']);
 for(const patch of [{platform:'MacIntel'},{screen_resolution:'1280x800',screen_avail_width:1920},{audio_context:{channel_count:8,max_channel_count:2}}])assert.throws(()=>api.loadConfig({...profile,fingerprint:{...profile.fingerprint,...patch}}))
 const bad=JSON.parse(JSON.stringify(profile));bad.fingerprint.webgl_contexts.webgl1.parameters.MAX_TEXTURE_SIZE=-1;assert.throws(()=>api.loadConfig(bad))
})

test('R01 private promise species, array species and regexp protocols resist later replacement',async()=>{
 const {ctx}=await context(['core/primordials']);
 await vm.runInContext(`(async()=>{
  const api=module.exports,leaks=[];const secret={host:64},raw=Promise.resolve(secret);
  const prior=Object.getOwnPropertyDescriptor(Promise.prototype,'constructor');
  Object.defineProperty(Promise.prototype,'constructor',{configurable:true,get(){leaks.push(this);return Promise}});
  const masked=api.promiseThen(raw,()=>({host:8}));
  Object.defineProperty(Promise.prototype,'constructor',prior);
  const result=await masked;
  Object.defineProperty(Array.prototype,'constructor',{configurable:true,get(){leaks.push(this);return Array}});
  RegExp.prototype.exec=function(){throw Error('poisoned exec')};RegExp.prototype[Symbol.split]=function(){throw Error('poisoned split')};
  resultArray=api.arrayMap([secret],()=>8);resultSplit=api.stringSplit('a b',/\\s+/);
  speciesResult={value:result.host,leaks:leaks.length,shape:Object.hasOwn(raw,'constructor')};
 })()`,ctx);
 assert.equal(ctx.speciesResult.value,8);assert.equal(ctx.speciesResult.leaks,0);assert.equal(ctx.speciesResult.shape,false);assert.deepEqual(Array.from(ctx.resultSplit),['a','b']);assert.deepEqual(Array.from(ctx.resultArray),[8]);
})

test('R01 profile copying never runs caller accessors or toJSON hooks',async()=>{
 const {api}=await context(['core/guard','core/config']);let called=0;
 const value={...profile};Object.defineProperty(value,'fingerprint',{enumerable:true,get(){called++;return profile.fingerprint}});
 assert.throws(()=>api.loadConfig(value),/accessors/);assert.equal(called,0);
 assert.throws(()=>api.loadConfig({...profile,toJSON(){called++;return profile}}),/JSON data/);assert.equal(called,0);
})

test('R05 marker-only frame scripts still run the private initializer',async()=>{
 const bootstrap=`window=globalThis;document={documentElement:{},querySelectorAll(){return [frame]}};class Frame{get contentWindow(){return child}get contentDocument(){return childDoc}addEventListener(){}removeEventListener(){}};HTMLIFrameElement=Frame;MutationObserver=class{constructor(cb){}observe(){}disconnect(){}};child={};childDoc={scripts:[{src:'https://fixture.test/__static/runtime.js',type:'application/json'}]};frame=new Frame();`;
 const {api}=await context(['core/guard','core/config','contexts/iframe'],{bootstrap});let calls=0;api.installIframePropagation(()=>{calls++;return 'ready'});assert.equal(calls,1);
})

test('R07 reentrant abort/reopen cancels stale blocked XHR completions',async()=>{
 const bootstrap=`window=globalThis;document={baseURI:'https://fixture.test/'};class E{constructor(type){this.type=type}};Event=E;ProgressEvent=E;EventTarget=class{constructor(){this.handlers={}}addEventListener(type,fn){(this.handlers[type]??=[]).push(fn)}dispatchEvent(event){for(const fn of this.handlers[event.type]||[])fn(event);return true}};class X extends EventTarget{constructor(){super();this.rs=0;this.responseType=''}get readyState(){if(!(this instanceof X))throw TypeError('receiver');return this.rs}get status(){return 0}get statusText(){return ''}get responseURL(){return ''}get responseText(){return ''}get response(){return ''}open(method,url){String(method);String(url);this.rs=1;this.dispatchEvent(new Event('readystatechange'))}send(){throw Error('blocked native send reached')}abort(){this.rs=0}setRequestHeader(){}};XMLHttpRequest=X;`;
 const {ctx,api}=await context(['core/guard','core/config','privacy/beacon-blackhole'],{bootstrap});api.getRuntime().nativeRefs={xhrPrototype:ctx.XMLHttpRequest.prototype,xhrOpen:ctx.XMLHttpRequest.prototype.open,xhrSend:ctx.XMLHttpRequest.prototype.send};api.installBeaconBlackhole();
 const result=await vm.runInContext(`(async()=>{const rows=[];for(const boundary of ['loadstart','readystatechange','load'])for(const action of ['abort','reopen']){
  const xhr=new XMLHttpRequest(),events=[];xhr.open('GET','https://play.google.com/log');let triggered=false;
  for(const name of ['loadstart','readystatechange','abort','load','loadend'])xhr.addEventListener(name,()=>{events.push(name);if(name===boundary&&!triggered){triggered=true;if(action==='abort')xhr.abort();else xhr.open('GET','https://play.google.com/new');}});
  xhr.send();await new Promise(resolve=>setTimeout(resolve,5));rows.push({boundary,action,events});
 }return rows})()`,ctx);
 for(const row of result){const events=Array.from(row.events);if(row.boundary==='loadstart')assert.equal(events.includes('load'),false);if(row.boundary==='readystatechange')assert.equal(events.includes('load'),false);assert.ok(events.filter(name=>name==='loadend').length<=1,JSON.stringify(row));}
})

test('R08 profile Date construction/setters handle DST gaps, overlaps, invalid dates and UTC borrowing',async()=>{
 const {ctx,api}=await context(['core/guard','core/config','identity/timezone']);api.getRuntime().nativeRefs={intlDateTimeFormat:vm.runInContext('Intl.DateTimeFormat',ctx)};api.installTimezone();
 const row=vm.runInContext(`(()=>{let conversions=0;const gap=new Date(2026,2,8,2,30),overlap=new Date(2026,10,1,1,30),objectDate=new Date({[Symbol.toPrimitive](hint){conversions++;return '2026-01-01T07:00:00'}});return{gap:gap.toISOString(),overlap:overlap.toISOString(),object:objectDate.toISOString(),conversions,invalid:Number.isNaN(new Date(NaN).getHours()),utc:Date.prototype.getUTCHours.call(new Date('2026-01-01T12:00Z'))}})()`,ctx);
 assert.equal(row.gap,'2026-03-08T07:30:00.000Z');assert.equal(row.overlap,'2026-11-01T05:30:00.000Z');assert.equal(row.object,'2026-01-01T12:00:00.000Z');assert.equal(row.conversions,1);assert.equal(row.invalid,true);assert.equal(row.utc,12);
})

test('R11 explicit omitted device kinds are excluded and repeated-kind labels use distinct profile entries',async()=>{
 const bootstrap=`window=globalThis;class Device{constructor(kind,id,label){this.k=kind;this.id=id;this.l=label}get kind(){if(!(this instanceof Device))throw TypeError('receiver');return this.k}get deviceId(){return this.id}get groupId(){return this.id+'-group'}get label(){return this.l}};MediaDeviceInfo=Device;navigator={mediaDevices:{enumerateDevices(){return Promise.resolve([new Device('audioinput','m1','host1'),new Device('audioinput','m2','host2'),new Device('videoinput','c1','hostcam')])}}};`;
 const {ctx,api}=await context(['core/guard','core/config','spoofing/media-devices'],{bootstrap});api.loadConfig({...profile,fingerprint:{...profile.fingerprint,media_devices:[{kind:'audioinput',label:'Mic One'},{kind:'audioinput',label:'Mic Two'}]}});api.installMediaDevicesSpoof();
 const rows=await vm.runInContext(`navigator.mediaDevices.enumerateDevices().then(list=>list.map(d=>({kind:d.kind,label:d.label,id:d.deviceId})))`,ctx);
 assert.equal(rows.length,2);assert.deepEqual(Array.from(rows,row=>row.label),['Mic One','Mic Two']);assert.ok(rows.every(row=>row.kind==='audioinput'&&/^[0-9a-f]{64}$/.test(row.id)));
})

test('R12 equal font metrics are independent of unrelated reads and content updates invalidate the cache',async()=>{
 const {ctx,api}=await context(['core/guard','identity/fonts']);vm.runInContext(`class H{constructor(text){this.textContent=text}get offsetWidth(){return 100}get offsetHeight(){return 20}};HTMLElement=H;window=globalThis;a=new H('same');b=new H('same');other=new H('unrelated');`,ctx);
 api.getRuntime().nativeRefs={defineProperty:Object.defineProperty,getOwnPropertyDescriptor:Object.getOwnPropertyDescriptor,HTMLElementPrototype:ctx.HTMLElement.prototype};api.getRuntime().entropy={origin:'fixture',sessionId:'fixed',hash:text=>text.endsWith('changed')?0:2};api.installFontMetrics();
 const result=vm.runInContext(`(()=>{const first=a.offsetWidth;other.offsetWidth;const second=b.offsetWidth;a.textContent='changed';return [first,second,a.offsetWidth]})()`,ctx);assert.deepEqual(Array.from(result),[101,101,99]);
})

test('R15 redacted readback is source-independent while sparse noise is not accepted as normalization',async()=>{
 const {ctx,api}=await context(['spoofing/canvas']);
 const model={entropy:{origin:'x',sessionId:'x',hash:()=>7,rng:()=>()=>0.5}},fp={canvas_readback_mode:'redacted',canvas_redaction_color:[7,11,19,255]};
 const first=vm.runInContext('({data:new Uint8Array(64).fill(10),width:4,height:4})',ctx),second=vm.runInContext('({data:new Uint8Array(64).fill(220),width:4,height:4})',ctx);
 api.injectCanvasNoise(first,model,fp,{});api.injectCanvasNoise(second,model,fp,{});assert.deepEqual(Array.from(first.data),Array.from(second.data));assert.deepEqual(Array.from(first.data.slice(0,4)),[7,11,19,255]);
 const sparse=vm.runInContext('({data:new Uint8Array(256).fill(100),width:32,height:2})',ctx),baseline=Array.from(sparse.data);
 api.injectCanvasNoise(sparse,model,{}, {small_canvas_threshold:16,small_canvas_stride:20,default_stride:10,noise_probability:1,delta_min:1,delta_max:1,integer_delta:true,touch_alpha:false});
 const error=Array.from(sparse.data).reduce((sum,value,index)=>sum+Math.abs(value-baseline[index]),0)/baseline.length;
 assert.ok(error>0&&error<.3,'Even maximal eligibility at the existing stride remains inside the one-byte approximate matcher');
})

test('R16 resource budgets reject before allocation and return to baseline after idempotent release',async()=>{
 const {api}=await context(['core/resources']);const budget=api.createResourceBudget(4096,2),release=budget.reserve(8,8),other=budget.reserve(8,8);
 assert.throws(()=>budget.reserve(1,1),/budget/);assert.throws(()=>budget.reserve(-1,-1),/budget/);assert.throws(()=>budget.reserve(1000000,1000000),/budget/);release();release();other();assert.deepEqual({...budget.counters()},{bytes:0,operations:0});
})

test('R19 async installers are rejected before executing and rolled-back held getters reject',async()=>{
 const {ctx,api}=await context(['core/patches','core/descriptors']);const target={};let ran=false,held;
 assert.throws(()=>api.transaction(async()=>{ran=true}),/synchronous/);assert.equal(ran,false);
 const bound=vm.runInContext('(async function(){globalThis.asyncRan=true}).bind(null)',ctx);assert.throws(()=>api.transaction(bound),/synchronous/);assert.equal(ctx.asyncRan,undefined);
 Object.defineProperty(target,'value',{get(){return 64},configurable:true});assert.throws(()=>api.transaction(()=>{api.replaceGetter(target,'value',()=>8);held=Object.getOwnPropertyDescriptor(target,'value').get;throw Error('rollback')}),/rollback/);
 assert.equal(target.value,64);assert.throws(()=>held.call(target),/disposed/);let cleanup=0;api.transaction(()=>api.onDispose(()=>cleanup++));api.disposeRealm();api.disposeRealm();assert.equal(cleanup,1);
})

test('R03 real installer separates identical masked offers, converts SDP dictionaries once and rejects late closed-peer results',async()=>{
 const bootstrap=`window=globalThis;class Peer{constructor(){this.address='10.0.0.1'}createOffer(){if(this.delayed)return new Promise(resolve=>this.resolve=resolve);return Promise.resolve({type:'offer',sdp:'v=0\\r\\nc=IN IP4 '+this.address+'\\r\\na=candidate:1 1 udp 1 '+this.address+' 1234 typ host\\r\\n'})}setLocalDescription(value){this.accepted={sdp:String(value.sdp),type:String(value.type)};return Promise.resolve()}restartIce(){}close(){}};RTCPeerConnection=Peer;`;
 const {ctx,api}=await context(['core/guard','core/config','spoofing/webrtc'],{bootstrap});api.getRuntime().nativeRefs={peerPrototype:ctx.RTCPeerConnection.prototype,RTCPeerConnection:ctx.RTCPeerConnection};api.installWebRTCSpoof();
 const rows=await vm.runInContext(`(async()=>{const a=new RTCPeerConnection(),b=new RTCPeerConnection();b.address='10.0.0.2';const first=await a.createOffer(),second=await b.createOffer();const reads=[];await a.setLocalDescription({get sdp(){reads.push('sdp');return first.sdp},get type(){reads.push('type');return first.type}});await b.setLocalDescription({...second});const late=new RTCPeerConnection();late.delayed=true;const pending=late.createOffer();late.close();late.resolve({type:'offer',sdp:'v=0'});let expired;try{await pending}catch(error){expired=error.name}return{equal:first.sdp===second.sdp,a:a.accepted.sdp,b:b.accepted.sdp,reads,expired}})()`,ctx);
 assert.equal(rows.equal,true);assert.ok(rows.a.includes('10.0.0.1'));assert.ok(!rows.a.includes('10.0.0.2'));assert.ok(rows.b.includes('10.0.0.2'));assert.deepEqual(Array.from(rows.reads),['sdp','type']);assert.equal(rows.expired,'AbortError');
})

test('R03 explicit relay-routing observations keep usable TURN endpoints and still mask related host addresses',async()=>{
 const {api}=await context(['spoofing/webrtc']);const line='candidate:1 1 udp 123 198.51.100.44 1234 typ relay raddr 10.0.0.5 rport 5678';
 const masked=api.sanitizeCandidateLine(line,{webrtc_observation_policy:'preserve-relay-routing',webrtc_ip:'192.0.2.55'});assert.ok(masked.includes('198.51.100.44 1234 typ relay'));assert.ok(!masked.includes('10.0.0.5'));assert.ok(masked.includes('raddr 192.0.2.55'));
})
test('R17 analyser paths retain native validation and never modify unused trailing slots',async()=>{
 const bootstrap=`window=globalThis;class A{get frequencyBinCount(){return 4}get fftSize(){return 8}getFloatFrequencyData(data){if(!(this instanceof A))throw TypeError('receiver');for(let i=0;i<4;i++)data[i]=-20}getFloatTimeDomainData(data){if(!(this instanceof A))throw TypeError('receiver');for(let i=0;i<8;i++)data[i]=.1}getByteFrequencyData(data){if(!(this instanceof A))throw TypeError('receiver');for(let i=0;i<4;i++)data[i]=100}getByteTimeDomainData(data){if(!(this instanceof A))throw TypeError('receiver');for(let i=0;i<8;i++)data[i]=128}};AnalyserNode=A;`;
 const {ctx,api}=await context(['core/guard','core/config','spoofing/audio'],{bootstrap});api.getRuntime().nativeRefs={analyserPrototype:ctx.AnalyserNode.prototype,analyserGetFloatFrequencyData:ctx.AnalyserNode.prototype.getFloatFrequencyData};api.getRuntime().entropy={sessionId:'fixed',hash:()=>7,rng:()=>()=>.5};api.installAudioSpoof();
 const rows=vm.runInContext(`(()=>{const a=new AnalyserNode(),rows=[];for(const name of ['getFloatFrequencyData','getFloatTimeDomainData','getByteFrequencyData','getByteTimeDomainData']){const array=name.includes('Float')?new Float32Array(16).fill(42):new Uint8Array(16).fill(42);a[name](array);const limit=name.includes('Frequency')?4:8;rows.push({tail:Array.from(array.slice(limit)),head:array[0]});}return rows})()`,ctx);
 for(const row of rows)assert.ok(row.tail.every(value=>value===42));assert.notEqual(rows[2].head,100);assert.notEqual(rows[3].head,128);
})
test('R19 pending normalization from a rolled-back owner rejects before touching a native result',async()=>{
 const {ctx,api}=await context(['core/patches','core/descriptors','core/primordials']);const target={get(){return new Promise(resolve=>target.resolve=resolve)}};let pending,touched=false;
 assert.throws(()=>api.transaction(()=>{api.mapMethod(target,'get',promise=>api.promiseThen(promise,value=>{touched=true;return value}));pending=target.get();throw Error('rollback')}),/rollback/);
 target.resolve({host:64});await assert.rejects(pending,/disposed/);assert.equal(touched,false);
})
test('R12 configured font-query policy hides native installed-font answers without replacing glyph rendering',async()=>{
 const bootstrap=`window=globalThis;class CSS{setProperty(key,value){this.value=value.replace(/^.*?px\\s+/,'')}getPropertyValue(){return this.value}};CSSStyleDeclaration=CSS;class H{get style(){return this.s??=new CSS()}get offsetWidth(){return 100}get offsetHeight(){return 20}};HTMLElement=H;class D{createElement(){return new H()}};Document=D;class Fonts{get status(){if(!(this instanceof Fonts))throw TypeError('receiver');return 'loaded'}check(text){if(!(this instanceof Fonts))throw TypeError('receiver');if(!text.includes('px'))throw DOMException('syntax','SyntaxError');return false}};document=new D();document.fonts=new Fonts();`;
 const {ctx,api}=await context(['core/guard','core/config','identity/fonts'],{bootstrap});api.getRuntime().nativeRefs={defineProperty:Object.defineProperty,getOwnPropertyDescriptor:Object.getOwnPropertyDescriptor,HTMLElementPrototype:ctx.HTMLElement.prototype};api.getRuntime().entropy={origin:'fixture',sessionId:'fixed',hash:()=>7};api.loadConfig({...profile,fingerprint:{...profile.fingerprint,fonts:['Arial']}});api.installFontMetrics();
 assert.equal(vm.runInContext(`document.fonts.check('16px Arial')`,ctx),true);assert.equal(vm.runInContext(`document.fonts.check('16px "host-private-font"')`,ctx),false);assert.throws(()=>vm.runInContext(`document.fonts.check.call({},'16px Arial')`,ctx),/receiver/);
})
test('R01/R02 private iterator bookkeeping is absent from public browser arrays',async()=>{
 const bootstrap=`window=globalThis;class N{get languages(){return Object.freeze(['host'])}get language(){return 'host'}get userAgent(){return 'host'}get platform(){return 'host'}get hardwareConcurrency(){return 64}};navigator=new N();`;
 const {ctx,api}=await context(['core/guard','core/config','identity/navigator'],{bootstrap});api.installNavigator();
 const result=vm.runInContext(`({symbols:Object.getOwnPropertySymbols(navigator.languages).length,frozen:Object.isFrozen(navigator.languages),same:navigator.languages===navigator.languages})`,ctx);
 assert.equal(result.symbols,0);assert.equal(result.frozen,true);assert.equal(result.same,true);
})
test('R01/R19 retried descriptor patches retain the first original rather than capturing a later page replacement',async()=>{
 const {api}=await context(['core/patches','core/descriptors']);const target={};let pageCalls=0;Object.defineProperty(target,'cpu',{get(){return 64},configurable:true});
 assert.throws(()=>api.transaction(()=>{api.replaceGetter(target,'cpu',()=>8);throw Error('fail')}),/fail/);
 Object.defineProperty(target,'cpu',{get(){pageCalls++;return 999},configurable:true});
 api.transaction(()=>api.replaceGetter(target,'cpu',native=>native/8));assert.equal(target.cpu,8);assert.equal(pageCalls,0);
})
test('R01 poisoned array iteration cannot acquire private rollback closures or disable URL policy',async()=>{
 const {ctx}=await context(['core/patches','core/descriptors','privacy/beacon-blackhole']);
 const result=vm.runInContext(`(()=>{const api=module.exports;const target={};Object.defineProperty(target,'cpu',{get(){return 64},configurable:true});let hooks=0;
  Array.prototype[Symbol.iterator]=function(){hooks++;throw Error('untrusted iterator')};
  const originalURL=URL,beforeHost=Object.getOwnPropertyDescriptor(URL.prototype,'hostname');Object.defineProperty(URL.prototype,'hostname',{get(){throw Error('untrusted URL getter')},configurable:true});URL=function(){throw Error('untrusted URL constructor')};
  try{api.transaction(()=>{api.replaceGetter(target,'cpu',()=>8);throw Error('rollback')});}catch(error){if(error.message!=='rollback')throw error;}
  const result={hooks,cpu:target.cpu,blocked:api.matchesPrivacyRule('https://play.google.com/log',[{hostSuffix:'play.google.com',pathPrefix:'/log'}],'https://fixture.test/')};Object.defineProperty(originalURL.prototype,'hostname',beforeHost);URL=originalURL;return result;})()`,ctx);
 assert.equal(result.hooks,0);assert.equal(result.cpu,64);assert.equal(result.blocked,true);
})
test('R01 storage never obtains a native quota dictionary for an inherited then hook to observe',async()=>{
 const bootstrap=`window=globalThis;class Storage{estimate(){nativeEstimateCalls++;return Promise.resolve({usage:999999,quota:999999999})}persisted(){if(!(this instanceof Storage))return Promise.reject(TypeError('receiver'));return Promise.resolve(false)}};nativeEstimateCalls=0;navigator={storage:new Storage()};`;
 const {ctx,api}=await context(['core/guard','core/config','capabilities/storage'],{bootstrap});api.installStorage();
 const row=await vm.runInContext(`(async()=>{const seen=[];Object.defineProperty(Object.prototype,'then',{configurable:true,get(){if(Object.hasOwn(this,'quota'))seen.push(this.quota);return undefined}});try{const estimate=await navigator.storage.estimate();return {quota:estimate.quota,usage:estimate.usage,calls:nativeEstimateCalls,seen};}finally{delete Object.prototype.then;}})()`,ctx);
 assert.equal(row.calls,0);assert.equal(row.quota,profile.fingerprint.storage_quota);assert.ok(Array.from(row.seen).every(value=>value===profile.fingerprint.storage_quota));
})
