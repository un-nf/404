const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http')
const playwright=require(process.env.STATIC_PLAYWRIGHT_MODULE||'playwright'),root=path.resolve(__dirname,'..')
const engine=process.env.STATIC_BROWSER_ENGINE||'chromium',profile=JSON.parse(fs.readFileSync(path.join(root,`profiles/${engine==='firefox'?'firefox':'chrome'}-windows.json`)))
const bundle=fs.readFileSync(path.join(root,'assets/js/dist/runtime.bundle.js'))
const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/runtime.js'?'text/javascript':'text/html');res.end(req.url==='/runtime.js'?bundle:`<!doctype html><script>
window.nativeBitmap=createImageBitmap;window.nativeRead=CanvasRenderingContext2D.prototype.getImageData;window.nativeURL=HTMLCanvasElement.prototype.toDataURL;
window.failureMode=false;window.bitmapCalls=0;window.intermediate=null;window.closedCount=0;const close=ImageBitmap.prototype.close;
ImageBitmap.prototype.close=function(){closedCount++;return close.call(this)};
window.createImageBitmap=function(...args){if(failureMode&&++bitmapCalls===2)return Promise.reject(Error('replacement failure'));return nativeBitmap(...args).then(bitmap=>{if(failureMode)intermediate=bitmap;return bitmap})};
</script><script src="/runtime.js" data-static-config-b64="${Buffer.from(JSON.stringify(profile)).toString('base64')}"></script>`)})
async function main(){await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await playwright[engine].launch({headless:true,...(process.env.STATIC_BROWSER_EXECUTABLE?{executablePath:process.env.STATIC_BROWSER_EXECUTABLE}:{})})
 try{const page=await browser.newPage();await page.goto(`http://localhost:${server.address().port}/`)
 const checks=await page.evaluate(async()=>{
  const checks={},canvas=document.createElement('canvas');canvas.width=8;canvas.height=6
  const ctx=canvas.getContext('2d');ctx.fillStyle='rgba(160,80,40,.5)';ctx.fillRect(0,0,4,6);ctx.fillStyle='#1234cc';ctx.fillRect(4,0,4,6)
  const original=Array.from(nativeRead.call(ctx,0,0,8,6).data)
  function pixels(bitmap){const copy=document.createElement('canvas');copy.width=bitmap.width;copy.height=bitmap.height;const c=copy.getContext('2d');c.drawImage(bitmap,0,0);return Array.from(nativeRead.call(c,0,0,copy.width,copy.height).data)}
  const image=new Image();image.src=nativeURL.call(canvas);await image.decode();const blob=await(await fetch(image.src)).blob()
  const prior=await nativeBitmap(canvas)
  for(const [name,input] of [['image',image],['blob',blob],['bitmap',prior],['imageData',new ImageData(new Uint8ClampedArray(original),8,6)]]){
   const expected=await nativeBitmap(input,{premultiplyAlpha:'none',colorSpaceConversion:'none'}),actual=await createImageBitmap(input,{premultiplyAlpha:'none',colorSpaceConversion:'none'})
   checks[name+'Decode']=JSON.stringify(pixels(actual))===JSON.stringify(pixels(expected));actual.close();expected.close()
  }
  prior.close()
  for(const alpha of ['none','premultiply','default'])for(const color of ['none','default']){
   let reads=0;const options={imageOrientation:'flipY',resizeWidth:4,resizeHeight:3,colorSpaceConversion:color,get premultiplyAlpha(){reads++;return alpha}}
   const expected=await nativeBitmap(canvas,{...options}),before=reads,actual=await createImageBitmap(canvas,options),a=pixels(actual),b=pixels(expected)
   checks[alpha+'-'+color]=actual.width===4&&actual.height===3&&reads===before+1&&a.every((v,i)=>i%4===3?v===b[i]:Math.abs(v-b[i])<=2)
   actual.close();expected.close()
  }
  const transparent=document.createElement('canvas');transparent.width=4;transparent.height=4;transparent.getContext('2d')
  const clear=await createImageBitmap(transparent);checks.transparent=pixels(clear).every(value=>value===0);clear.close()
  checks.sourcePreserved=JSON.stringify(original)===JSON.stringify(Array.from(nativeRead.call(ctx,0,0,8,6).data))
  const glCanvas=document.createElement('canvas');glCanvas.width=16;glCanvas.height=16;const gl=glCanvas.getContext('webgl',{preserveDrawingBuffer:true})
  if(gl){gl.clearColor(.2,.4,.6,.5);gl.clear(gl.COLOR_BUFFER_BIT);const expected=await nativeBitmap(glCanvas),actual=await createImageBitmap(glCanvas);checks.webglExport=pixels(actual).every((v,i)=>i%4===3?v===pixels(expected)[i]:Math.abs(v-pixels(expected)[i])<=2);actual.close();expected.close()}
  failureMode=true;bitmapCalls=0;const beforeClose=closedCount
  try{await createImageBitmap(canvas);checks.replacementRejects=false}catch(e){checks.replacementRejects=e.message==='replacement failure'}
  checks.intermediateClosed=intermediate.width===0&&closedCount===beforeClose+1
  failureMode=false
  try{await createImageBitmap(canvas,{resizeWidth:0});checks.invalidOptions=false}catch(e){checks.invalidOptions=e instanceof DOMException||e instanceof TypeError}
  return checks
 });assert.ok(Object.values(checks).every(Boolean),JSON.stringify(checks));console.log(JSON.stringify({engine,version:browser.version(),checks},null,2))
 }finally{await browser.close();await new Promise(r=>server.close(r))}}
main().catch(error=>{console.error(error);process.exitCode=1})
