const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process'),vm=require('node:vm');
const repo=path.resolve(__dirname,'../../..');
const run=(script,args=[])=>spawnSync(process.execPath,[path.join(repo,'.github/scripts',script),...args],{encoding:'utf8',windowsHide:true});
test('R22 release helpers reject missing paths rather than scanning the current directory',()=>{for(const script of ['build-static-release-manifest.mjs','build-distro-release-manifest.mjs']){const result=run(script,['--version','audit']);assert.notEqual(result.status,0);assert.match(result.stderr,/Usage/);}});
test('R22 streamed artifact hashes preserve the release format and duplicate basenames reject',()=>{
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'static-release-audit-'));
 try{const input=path.join(temporary,'input'),output=path.join(temporary,'manifest.json');fs.mkdirSync(path.join(input,'nested'),{recursive:true});const bytes=crypto.randomBytes(2*1024*1024+1);fs.writeFileSync(path.join(input,'static_proxy.exe'),bytes);
  const result=run('build-static-release-manifest.mjs',['--input',input,'--output',output,'--version','audit']);assert.equal(result.status,0,result.stderr);const manifest=JSON.parse(fs.readFileSync(output));assert.equal(manifest.artifacts[0].sha256,crypto.createHash('sha256').update(bytes).digest('hex'));
  fs.writeFileSync(path.join(input,'nested','STATIC_PROXY.EXE'),'duplicate');const duplicate=run('build-static-release-manifest.mjs',['--input',input,'--output',output,'--version','audit']);assert.notEqual(duplicate.status,0);assert.match(duplicate.stderr,/Ambiguous/);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
test('R22 retired behavioral entry creates no globals, queue, payload mutations or socket wrapper',()=>{
 const source=fs.readFileSync(path.join(repo,'src/STATIC_proxy/assets/js/behavioral_noise_v1.js'),'utf8'),socket=function(){};
 const target={WebSocket:socket};const context=vm.createContext({window:target});vm.runInContext(source,context);assert.deepEqual(Object.keys(target),['WebSocket']);assert.equal(target.WebSocket,socket);
 target.__STATIC_BEHAVIOR_ENABLED=true;assert.throws(()=>vm.runInContext(source,context),/retired/);
});
test('R20/R21 matched build-set verification rejects changed output and records every schema dependency',()=>{
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'static-bundle-audit-')),build=path.join(repo,'src/STATIC_proxy/build/build.js'),env={...process.env,STATIC_BUNDLE_OUTFILE:path.join(temporary,'runtime.bundle.js')};
 const execute=args=>spawnSync(process.execPath,[build,...args],{env,encoding:'utf8',windowsHide:true});
 try{const result=execute([]);assert.equal(result.status,0,result.stderr);const metadata=JSON.parse(fs.readFileSync(path.join(temporary,'bundle-set.json')));assert.ok(metadata.schemas['webgl-parameters.json']);assert.ok(metadata.sources['core/primordials.js']);assert.equal(execute(['--verify']).status,0);
  fs.appendFileSync(path.join(temporary,'worker-module.bundle.js'),'\n// altered');const rejected=execute(['--verify']);assert.notEqual(rejected.status,0);assert.match(rejected.stderr,/Mismatched bundle set/);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
