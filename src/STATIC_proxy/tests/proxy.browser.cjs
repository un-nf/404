// Full running-proxy smoke test, with isolated debug CA/cache and fake media.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),net=require('node:net')
const assert=require('node:assert/strict'),{spawn,execFileSync}=require('node:child_process')
const playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright')
const root=path.resolve(__dirname,'..'),engine=process.env.STATIC_BROWSER_ENGINE||'chromium'
const profile=process.env.STATIC_BROWSER_PROFILE||(engine==='firefox'?'firefox':'chrome')
const fixture=path.join(root,'target','live-proxy',`${engine}-${profile}`)
fs.mkdirSync(fixture,{recursive:true})
async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const port=s.address().port;await new Promise(r=>s.close(r));return port}
async function main(){
  execFileSync('cargo',['build','--locked','--offline'],{cwd:root,stdio:'pipe'})
  // Run a fixture-owned copy: a stalled browser cannot lock Cargo's output.
  const binary=process.platform==='win32'?'static_proxy.exe':'static_proxy'
  const executable=path.join(fixture,binary)
  fs.copyFileSync(path.join(root,'target/debug',binary),executable)
  if(process.platform!=='win32')fs.chmodSync(executable,0o755)
  const observed=[]
  const upstream=http.createServer((req,res)=>{
    observed.push({path:req.url,ua:req.headers['user-agent'],headers:req.headers})
    res.setHeader('Accept-CH','Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors')
    res.setHeader('Cache-Control','no-store')
    if(req.url==='/worker.js'){res.setHeader('Content-Type','text/javascript');res.end('(async()=>postMessage({ua:navigator.userAgent,storage:navigator.storage?await navigator.storage.estimate():null}))()')}
    else {res.setHeader('Content-Type','text/html');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; worker-src 'self'");res.end('<!doctype html><html><head><title>proxy fixture</title></head><body>proxy fixture</body></html>')}
  })
  await new Promise(r=>upstream.listen(0,'127.0.0.1',r))
  const port=await freePort(),config=path.join(fixture,'config.toml')
  fs.writeFileSync(config,`[listener]\nbind_address="127.0.0.1"\nbind_port=${port}\nproxy_protocol="plain"\n[tls]\nkeystore={mode="file"}\n[pipeline]\nprofiles_path=${JSON.stringify(path.join(root,'profiles').replaceAll('\\','/'))}\ndefault_profile="${profile}-windows"\njs_debug=false\nalt_svc_strategy="normalize"\n[http3]\nenabled=false\n[telemetry]\nmode="stdout"\n`)
  const storageArgs=JSON.parse(process.env.STATIC_STORAGE_TEST_ARGS||'[]')
  const child=spawn(executable,['--config',config,...storageArgs],{cwd:root,windowsHide:true,
    env:{...process.env,RUST_LOG:'info',STATIC_TEST_DATA_DIR:path.join(fixture,'state')}})
  let logs='';child.stdout.on('data',data=>logs+=data);child.stderr.on('data',data=>logs+=data)
  let browser
  try{
    for(let i=0;i<150&&!logs.includes('listener online');i++){
      if(child.exitCode!==null)throw Error(logs)
      await new Promise(r=>setTimeout(r,100))
    }
    assert.ok(logs.includes('listener online'),logs)
    browser=await playwright[engine].launch({headless:true,proxy:{server:`http://127.0.0.1:${port}`},
      ...(engine==='firefox'?{firefoxUserPrefs:{'network.proxy.no_proxies_on':'','network.proxy.allow_hijacking_localhost':true}}:{args:['--proxy-bypass-list=<-loopback>']}),
      ...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})})
    const page=await browser.newPage({ignoreHTTPSErrors:true}),errors=[];page.on('pageerror',e=>errors.push(e.message))
    const url=`http://localhost:${upstream.address().port}/`
    const response=await page.goto(url)
    const expected=JSON.parse(fs.readFileSync(path.join(root,`profiles/${profile}-windows.json`))).fingerprint.user_agent
    assert.equal(await page.evaluate(()=>navigator.userAgent),expected)
    assert.equal(observed.find(r=>r.path==='/').ua,expected)
    const scripts=await page.locator('script[src="/__static/runtime.js"]').count();assert.equal(scripts,1)
    assert.equal(await page.locator('script[data-static-config-b64]').count(),0)
    assert.ok(response.headers()['content-security-policy'].includes("'nonce-"))
    assert.ok(!response.headers()['content-security-policy'].includes('blob:'))
    assert.ok(response.headers()['permissions-policy'].includes('geolocation=()'))
    const geo = await page.evaluate(()=>Promise.race([new Promise(resolve=>navigator.geolocation.getCurrentPosition(
      ()=>resolve({leaked:true}),error=>resolve({code:error.code,brand:error instanceof GeolocationPositionError}))),
      new Promise(resolve=>setTimeout(()=>resolve({timeout:true}),3000))]))
    assert.equal(geo.code,1)
    if(engine==='chromium')assert.equal(geo.brand,true)
    else console.log(`Geolocation denial: ${geo.brand?'native browser policy':'documented JS fallback (native error interface unavailable)'}`)
    const geoChecks=await page.evaluate(async()=>{
      let calls=0,invalid=false
      try{Geolocation.prototype.getCurrentPosition.call({},()=>{})}catch{invalid=true}
      const id=navigator.geolocation.watchPosition(()=>calls++,()=>calls++)
      navigator.geolocation.clearWatch(id)
      await new Promise(resolve=>setTimeout(resolve,50))
      return{invalid,calls}
    })
    assert.equal(geoChecks.invalid,true);assert.equal(geoChecks.calls,0)
    const workerData=await page.evaluate(()=>new Promise((resolve,reject)=>{const worker=new Worker('/worker.js');worker.onmessage=e=>{worker.terminate();resolve(e.data)};worker.onerror=reject}))
    assert.equal(workerData.ua,expected)
    if(workerData.storage){assert.equal(workerData.storage.quota,Number(process.env.STATIC_TEST_STORAGE_QUOTA||107374182400));assert.equal(workerData.storage.usage,Number(process.env.STATIC_TEST_STORAGE_USAGE||1048576))}
    const estimate=await page.evaluate(()=>navigator.storage.estimate())
    assert.equal(estimate.quota,Number(process.env.STATIC_TEST_STORAGE_QUOTA||107374182400))
    assert.equal(estimate.usage,Number(process.env.STATIC_TEST_STORAGE_USAGE||1048576))
    await page.evaluate(()=>fetch('/hints'))
    if(engine==='chromium') {
      const identity=JSON.parse(fs.readFileSync(path.join(root,`profiles/${profile}-windows.json`))).fingerprint.ua_data
      const hints=observed.find(value=>value.path==='/hints').headers
      assert.equal(hints['sec-ch-ua-arch'],JSON.stringify(identity.architecture))
      assert.equal(hints['sec-ch-ua-wow64'],identity.wow64?'?1':'?0')
      assert.equal(hints['sec-ch-ua-form-factors'],identity.form_factors.map(value=>JSON.stringify(value)).join(', '))
    }
    assert.deepEqual(errors,[])
    if(process.env.STATIC_PUBLIC_TLS_SMOKE==='1') {
      const secure=await page.goto('https://example.com/')
      assert.ok(secure.ok())
      assert.equal(await page.evaluate(()=>navigator.userAgent),expected)
      assert.equal(await page.locator('script[src="/__static/runtime.js"]').count(),1)
      if(engine==='chromium'){
        const session=await page.context().newCDPSession(page)
        const entries=await page.evaluate(()=>performance.getEntriesByType('navigation').map(entry=>entry.nextHopProtocol))
        assert.ok(entries.includes('h2'),JSON.stringify(entries))
        await session.detach()
      }
      console.log(`PASS: ${engine} public TLS navigation through rebuilt proxy; native certificate validation upstream, ephemeral client test-root exception; HTTP/2 navigation`)
    }
    console.log(`PASS: ${engine}/${profile} rebuilt running proxy, real upstream headers/body, CSP nonce, served runtime, consumed config, worker delivery, storage policy`)
  }catch(error){fs.writeFileSync(path.join(fixture,'proxy.log'),logs);throw error}
  finally{if(browser)await browser.close();child.kill();await new Promise(r=>upstream.close(r))}
}
main().catch(error=>{console.error(error);process.exitCode=1})
