const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),vm=require('node:vm'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..'),profile=require('../profiles/chrome-windows.json')
const source=esbuild.build({stdin:{contents:`export * from './assets/js/src/core/guard.js';export * from './assets/js/src/core/config.js';export * from './assets/js/src/spoofing/webrtc.js';`,resolveDir:root},bundle:true,format:'cjs',write:false}).then(r=>r.outputFiles[0].text)
test('peer, sender and receiver stats retain reports while masking borrowed get/iteration/callback address paths',async()=>{
 const ctx=vm.createContext({module:{exports:{}},DOMException});vm.runInContext(await source,ctx);const api=ctx.module.exports;api.initRuntime();api.loadConfig(profile)
 vm.runInContext(`
 class Peer {getStats(){if(!(this instanceof Peer))return Promise.reject(TypeError('receiver'));return Promise.resolve(this.report)}}
 class Sender {getStats(){return Promise.resolve(this.report)}}class Receiver {getStats(){return Promise.resolve(this.report)}}
 Object.assign(globalThis,{RTCPeerConnection:Peer,RTCRtpSender:Sender,RTCRtpReceiver:Receiver});
 nativeAddress={type:'local-candidate',address:'198.51.100.33',relatedAddress:'10.1.2.3',ip:'2001:db8::123'};
 report=new Map([['candidate',nativeAddress]]);plain=new Map([['candidate',nativeAddress]]);
 `,ctx)
 api.getRuntime().nativeRefs={peerPrototype:ctx.RTCPeerConnection.prototype,RTCPeerConnection:ctx.RTCPeerConnection};api.installWebRTCSpoof()
 const observations=await vm.runInContext(`(async()=>{const rows=[];for(const Type of [RTCPeerConnection,RTCRtpSender,RTCRtpReceiver]){const p=new Type();p.report=report;const r=await p.getStats();let callback;r.forEach((value,key,collection)=>callback={value,key,collection});rows.push({same:r===report,get:r.get('candidate'),borrowed:Map.prototype.get.call(r,'candidate'),entries:[...r][0][1],values:[...r.values()][0],callback:callback.value,callbackIdentity:callback.collection===r})}return {rows,plain:plain.get('candidate')}})()`,ctx)
 for(const row of observations.rows){assert.equal(row.same,true);assert.equal(row.callbackIdentity,true);for(const key of ['get','borrowed','entries','values','callback']){assert.equal(row[key].address,profile.fingerprint.webrtc_ip||profile.fingerprint.ip_address||'192.0.2.1');assert.equal(row[key].relatedAddress,row[key].address);assert.equal(row[key].ip,profile.fingerprint.webrtc_ipv6||'2001:db8::1')}}
 assert.equal(observations.plain.address,'198.51.100.33');assert.equal(ctx.nativeAddress.relatedAddress,'10.1.2.3')
})
test('relay policy controls native construction and reconfiguration without inventing TURN infrastructure',async()=>{
 const ctx=vm.createContext({module:{exports:{}},DOMException});vm.runInContext(await source,ctx);const api=ctx.module.exports;api.initRuntime();api.loadConfig({...profile,fingerprint:{...profile.fingerprint,webrtc_transport_policy:'relay-only'}})
 vm.runInContext(`class Peer {constructor(config={}){this.setConfiguration(config)}setConfiguration(config){if(!(this instanceof Peer))throw TypeError('receiver');this.config={iceTransportPolicy:config.iceTransportPolicy||'all',iceServers:config.iceServers||[]}}getConfiguration(){return this.config}};globalThis.RTCPeerConnection=Peer;`,ctx)
 api.getRuntime().nativeRefs={peerPrototype:ctx.RTCPeerConnection.prototype,RTCPeerConnection:ctx.RTCPeerConnection};api.installWebRTCSpoof()
 assert.equal(vm.runInContext(`new RTCPeerConnection({iceTransportPolicy:'all'}).getConfiguration().iceTransportPolicy`,ctx),'relay')
 assert.equal(vm.runInContext(`p=new RTCPeerConnection();p.setConfiguration({iceTransportPolicy:'all',iceServers:[{urls:'turn:caller.example'}]});p.getConfiguration().iceTransportPolicy`,ctx),'relay')
 assert.equal(vm.runInContext(`p.getConfiguration().iceServers[0].urls`,ctx),'turn:caller.example')
 assert.throws(()=>vm.runInContext(`p.setConfiguration({iceTransportPolicy:'bogus'})`,ctx),/Invalid/)
 assert.throws(()=>vm.runInContext(`Peer.prototype.setConfiguration.call({}, {})`,ctx),/receiver/)
})
