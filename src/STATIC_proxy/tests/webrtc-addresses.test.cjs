const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),path=require('node:path'),esbuild=require('../build/node_modules/esbuild')
const root=path.resolve(__dirname,'..')
test('public, related, mDNS and IPv6 candidates expose only configured address observations without changing transport',async()=>{
 const build=await esbuild.build({stdin:{contents:`export {sanitizeCandidateLine} from './assets/js/src/spoofing/webrtc.js';`,resolveDir:root},bundle:true,format:'cjs',write:false})
 const ctx=vm.createContext({module:{exports:{}}});vm.runInContext(build.outputFiles[0].text,ctx);const mask=ctx.module.exports.sanitizeCandidateLine,fp={webrtc_ip:'192.0.2.55',webrtc_ipv6:'2001:db8::55',webrtc_udp_only:true}
 for(const source of ['candidate:1 1 udp 123 203.0.113.44 1234 typ srflx raddr 10.0.0.5 rport 5678','a=candidate:1 1 tcp 123 host.local 1234 typ host','candidate:1 1 udp 123 2001:db8:abcd::5 1234 typ relay raddr fe80::42 rport 5678']){
  const output=mask(source,fp)
  for(const ip of ['203.0.113.44','10.0.0.5','host.local','2001:db8:abcd::5','fe80::42'])assert.ok(!output.includes(ip),ip)
  assert.equal(output.includes(' tcp '),source.includes(' tcp '));assert.equal(output.includes('typ host'),source.includes('typ host'))
 }
})
