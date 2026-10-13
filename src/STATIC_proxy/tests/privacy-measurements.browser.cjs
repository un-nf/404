// Three independent measurements: recovery, repeat-visit linkage, persona fit.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto')
const assert=require('node:assert/strict'),playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright')
const root=path.resolve(__dirname,'..'),engine=process.env.STATIC_BROWSER_ENGINE||'chromium'
const profile=process.env.STATIC_BROWSER_PROFILE||(engine==='firefox'?'firefox':'chrome')
const raw=JSON.parse(fs.readFileSync(path.join(root,`profiles/${profile}-windows.json`)))
raw.startup_salt='public-known-fixture-salt'
const bundle=fs.readFileSync(path.join(root,'assets/js/dist/runtime.bundle.js'))
const server=http.createServer((req,res)=>{
  if(req.url==='/runtime.js'){res.setHeader('Content-Type','text/javascript');res.end(bundle)}
  else{res.setHeader('Content-Type','text/html');res.end(`<!doctype html><html><head><script>window.nativeRead=CanvasRenderingContext2D.prototype.getImageData;window.nativeExport=HTMLCanvasElement.prototype.toDataURL;window.nativeRate=Object.getOwnPropertyDescriptor(BaseAudioContext.prototype,"sampleRate").get;</script><script src="/runtime.js" data-static-config-b64="${Buffer.from(JSON.stringify(raw)).toString('base64')}"></script></head><body></body></html>`)}
})
async function main(){
  await new Promise(r=>server.listen(0,'127.0.0.1',r))
  const browser=await playwright[engine].launch({headless:true,...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})})
  const runs=[],vectors=[],baselines=[]
  try{
    for(let visit=0;visit<5;visit++){
      const page=await browser.newPage();await page.goto(`http://localhost:${server.address().port}/`)
      const run=await page.evaluate(async()=>{
        const canvas=document.createElement('canvas');canvas.width=300;canvas.height=100
        const ctx=canvas.getContext('2d');ctx.fillStyle='#a247dd';ctx.fillRect(0,0,300,100);ctx.font='17px Arial';ctx.fillStyle='#34cc82';ctx.fillText('Fingerprint comparison Ω',9,42)
        const native=Array.from(nativeRead.call(ctx,0,0,300,100).data),masked=Array.from(ctx.getImageData(0,0,300,100).data)
        const repeat=Array.from(ctx.getImageData(0,0,300,100).data)
        const nativeURL=nativeExport.call(canvas),first=canvas.toDataURL(),second=canvas.toDataURL()
        const pending=new Promise(resolve=>canvas.toBlob(resolve));ctx.fillStyle='#00aa00';ctx.fillRect(0,0,300,100)
        const afterDraw=Array.from(nativeRead.call(ctx,0,0,300,100).data);await pending
        const afterExport=Array.from(nativeRead.call(ctx,0,0,300,100).data)
        const explicit=new AudioContext({sampleRate:44100});const rate=nativeRate.call(explicit);await explicit.close()
        return{native,masked,repeated:JSON.stringify(masked)===JSON.stringify(repeat),exportsStable:first===second,
          exportMasked:first!==nativeURL,sourcePreserved:JSON.stringify(afterDraw)===JSON.stringify(afterExport),explicitRate:rate,
          ua:navigator.userAgent,webgl:document.createElement('canvas').getContext('webgl')?.getParameter(37446)}
      })
      const hash=values=>crypto.createHash('sha256').update(Buffer.from(values)).digest('hex')
      vectors.push(run.masked);baselines.push(run.native)
      runs.push({nativeHash:hash(run.native),maskedHash:hash(run.masked),sameBytes:run.masked.filter((value,index)=>value===run.native[index]).length/run.native.length,
        repeated:run.repeated,exportsStable:run.exportsStable,exportMasked:run.exportMasked,sourcePreserved:run.sourcePreserved,
        explicitRate:run.explicitRate,ua:run.ua})
      await page.close()
    }
    const baseline=baselines[0],median=baseline.map((_,index)=>vectors.map(vector=>vector[index]).sort((a,b)=>a-b)[Math.floor(vectors.length/2)])
    const recoveredFraction=median.filter((value,index)=>value===baseline[index]).length/baseline.length
    const approximateErrors=vectors.map(vector=>vector.reduce((sum,value,index)=>sum+Math.abs(value-baseline[index]),0)/baseline.length)
    const approximateMatch=approximateErrors.every(error=>error<=1)
    const effectiveness={passed:!approximateMatch,approximateMatchAtOneByteMeanError:approximateMatch,meanAbsoluteByteErrors:approximateErrors,medianRecoveredByteFraction:recoveredFraction,threatModel:'one host, tracker has a historical clean pixel vector for this known drawing; five independent protected documents; no population or multi-machine inference'}
    const report={effectiveness,engine,version:browser.version(),profile,
      hostRecovery:{unchangedByteFractions:runs.map(r=>r.sameBytes),interpretation:'Sparse noise retains substantial host pixel structure; changed hashes are not a recovery defense proof.'},
      repeatVisitLinkage:{nativeUniqueHashes:new Set(runs.map(r=>r.nativeHash)).size,maskedUniqueHashes:new Set(runs.map(r=>r.maskedHash)).size,scope:'five documents, same public bootstrap salt, one origin and machine; no multi-machine/ad-tech unlinkability claim'},
      personaFit:{uaMatches:runs.every(r=>r.ua===raw.fingerprint.user_agent),explicitSampleRatesPreserved:runs.every(r=>r.explicitRate===44100),interpretation:'Observation normalization, not faithful GPU/font/audio engine emulation.'},
      functionality:{repeatReadStable:runs.every(r=>r.repeated),repeatExportStable:runs.every(r=>r.exportsStable),maskedExports:runs.every(r=>r.exportMasked),pendingExportPreservesDrawing:runs.every(r=>r.sourcePreserved)},runs}
    fs.mkdirSync(path.join(root,'target/privacy-measurements'),{recursive:true})
    fs.writeFileSync(path.join(root,`target/privacy-measurements/${engine}-${profile}.json`),JSON.stringify(report,null,2)+'\n')
    assert.ok(Object.values(report.functionality).every(Boolean));assert.ok(report.personaFit.uaMatches);assert.ok(report.personaFit.explicitSampleRatesPreserved)
    assert.ok(report.repeatVisitLinkage.maskedUniqueHashes>1,'Public salt must not determine all document noise')
    if(process.env.STATIC_PRIVACY_EFFECTIVENESS_GATE==='1')assert.equal(report.effectiveness.passed,true,'Approximate historical-baseline matching remains effective; C5 gate failed')
    console.log(JSON.stringify({engine,effectiveness:report.effectiveness,hostRecovery:report.hostRecovery,repeatVisitLinkage:report.repeatVisitLinkage,personaFit:report.personaFit,functionality:report.functionality},null,2))
  }finally{await browser.close();await new Promise(r=>server.close(r))}
}
main().catch(e=>{console.error(e);process.exitCode=1})
