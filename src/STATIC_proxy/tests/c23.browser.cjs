const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const http = require('node:http')
const { execFileSync } = require('node:child_process')
const playwright = require(process.env.STATIC_PLAYWRIGHT_MODULE || 'playwright')
const engine = process.env.STATIC_BROWSER_ENGINE || 'chromium'
const profileName = process.env.STATIC_BROWSER_PROFILE || (engine === 'firefox' ? 'firefox' : 'chrome')
const root = path.resolve(__dirname, '..')
const directory = path.join(root, 'target', 'c23-browser-fixtures')
execFileSync('cargo', ['test', '--locked', '--offline', 'export_worker_browser_fixtures'], {
  cwd: root, env: { ...process.env, STATIC_BROWSER_FIXTURE_DIR: directory, STATIC_BROWSER_PROFILE: profileName }, stdio: 'pipe',
})
const raw = JSON.parse(fs.readFileSync(path.join(root, `profiles/${profileName}-windows.json`), 'utf8'))
raw.startup_salt = 'browser-fixture-salt'
// Explicit fixture-only native transport exercises local operation/alias reversal.
// Shipped profiles remain relay-only; test that enforcement separately.
raw.fingerprint.webrtc_transport_policy='native'
raw.privacy_rules=[{hostSuffix:'localhost',pathPrefix:'/blocked'}]
// Test-only access to the existing private outcome snapshot, without handles.
const bundle = fs.readFileSync(path.join(directory, 'runtime.bundle.js'), 'utf8').replace(
  'runtime.failure = error ? String(error.message || error) : null;',
  'runtime.failure = error ? String(error.message || error) : null; globalThis.__fixtureReport = {state:runtime.state, outcomes:runtime.outcomes};')
const encoded = Buffer.from(JSON.stringify(raw)).toString('base64')
const observations = []
const server = http.createServer((request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname
  observations.push({ pathname, destination: request.headers['sec-fetch-dest'], mode: request.headers['sec-fetch-mode'] })
  const files = ['classic.js', 'module.js', 'shared.js', 'service.js', 'service-module.js']
  response.setHeader('Cache-Control', 'no-store')
  if (pathname === '/') {
    response.setHeader('Permissions-Policy','geolocation=()')
    response.setHeader('Feature-Policy',"geolocation 'none'")
    response.setHeader('Content-Type', 'text/html')
    response.end(`<!doctype html><html><head><script>
      window.expectedOffsets = ${JSON.stringify(raw.fingerprint.timezone === 'America/Denver' ? [420,360] : [300,240])};
      window.expectedProfile = ${JSON.stringify(raw.fingerprint)};
      window.before = {storage:navigator.storage,permissions:navigator.permissions,
        mediaCapabilities:navigator.mediaCapabilities,plugins:navigator.plugins,mimes:navigator.mimeTypes,
        ua:navigator.userAgentData,uaStable:navigator.userAgentData===navigator.userAgentData,
        brandRecordFrozen:navigator.userAgentData ? Object.isFrozen(navigator.userAgentData.brands[0]) : undefined,
        brandsStable:navigator.userAgentData ? navigator.userAgentData.brands===navigator.userAgentData.brands : undefined,
        uaGetter:Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgentData')?.get,
        battery:typeof navigator.getBattery,network:typeof navigator.connection,
        notification:window.Notification,getVoices:window.speechSynthesis?.getVoices,
        estimate:navigator.storage?.estimate,query:navigator.permissions?.query,
        decodingInfo:navigator.mediaCapabilities?.decodingInfo,
        enumerateDevices:navigator.mediaDevices?.enumerateDevices,
        deviceId:Object.getOwnPropertyDescriptor(MediaDeviceInfo.prototype,'deviceId')?.get,
        groupId:Object.getOwnPropertyDescriptor(MediaDeviceInfo.prototype,'groupId')?.get,
        deviceCaps:window.InputDeviceInfo?.prototype.getCapabilities,
        audioRate:window.BaseAudioContext&&Object.getOwnPropertyDescriptor(BaseAudioContext.prototype,'sampleRate')?.get,
        userAgent:Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgent')};
      </script><script src="/__static/runtime.js" data-static-config-b64="${encoded}"></script></head><body></body></html>`)
  } else if (pathname === '/__static/runtime.js') {
    response.setHeader('Content-Type', 'text/javascript'); response.end(bundle)
  } else if (pathname === '/__static/worker-module.js') {
    response.setHeader('Content-Type', 'text/javascript'); response.end(fs.readFileSync(path.join(directory, 'worker-module.bundle.js')))
  } else if (files.includes(pathname.slice(1))) {
    response.setHeader('Content-Type', 'text/javascript'); response.end(fs.readFileSync(path.join(directory, pathname.slice(1))))
  } else if (pathname === '/helper.js') {
    response.setHeader('Content-Type', 'text/javascript'); response.end('self.helper = navigator.userAgent;')
  } else if (pathname === '/dependency.js') {
    response.setHeader('Content-Type', 'text/javascript'); response.end('export const snapshot = navigator.userAgent;')
  } else if (pathname === '/plain.html') {
    response.setHeader('Content-Type', 'text/html'); response.end('<html><body>unproxied</body></html>')
  } else { response.statusCode = 404; response.end() }
})

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://localhost:${server.address().port}`
  const browser = await playwright[engine].launch({ headless: true,
    ...(engine === 'firefox' ? {firefoxUserPrefs:{'media.navigator.streams.fake':true,'media.navigator.permission.disabled':true}} :
      {args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']}),
    ...(process.env.STATIC_BROWSER_EXECUTABLE ? { executablePath: process.env.STATIC_BROWSER_EXECUTABLE } : {}) })
  try {
    const page = await browser.newPage()
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.goto(origin)
    // Exercise populated inventories, not just an empty initial voice list.
    await page.evaluate(async () => {
      for(let attempt=0;attempt<50;attempt++) {
        if(before.getVoices.call(speechSynthesis).length) break
        await new Promise(resolve=>setTimeout(resolve,100))
      }
    })
    const shapes = await page.evaluate(async () => {
      const n = navigator, b = before
      const checks = {}
      const pdfAvailable=expectedProfile.pdf_viewer_enabled&&b.plugins.length===5&&b.mimes.length===2&&['PDF Viewer','Chrome PDF Viewer','Chromium PDF Viewer','Microsoft Edge PDF Viewer','WebKit built-in PDF'].every((name,index)=>b.plugins[index].name===name)
      if(expectedProfile.pdf_viewer_enabled&&!pdfAvailable){try{n.pdfViewerEnabled;checks.pdfFlag=false}catch(e){checks.pdfFlag=e.name==='SecurityError'}}
      else checks.pdfFlag = n.pdfViewerEnabled === expectedProfile.pdf_viewer_enabled
      checks.installation = window.__fixtureReport.state === 'ready'
      const blocked=await fetch(new URL('/blocked',location.href))
      checks.blockedFetch=blocked instanceof Response&&blocked.status===204&&await blocked.text()===''
      const controller=new AbortController();controller.abort('fixture-abort')
      try{await fetch('/blocked',{signal:controller.signal});checks.blockedAbort=false}catch(e){checks.blockedAbort=e==='fixture-abort'}
      const xhr=new XMLHttpRequest();let loads=0,ends=0
      const completed=new Promise(resolve=>{xhr.onload=()=>{loads++;resolve()};xhr.addEventListener('loadend',()=>ends++)})
      xhr.open('GET','/blocked');xhr.responseType='json';xhr.send();await completed
      checks.blockedXHR=loads===1&&ends===1&&xhr.status===204&&xhr.readyState===4&&xhr.response===null&&!Object.hasOwn(xhr,'readyState')
      try{XMLHttpRequest.prototype.send.call({});checks.xhrReceiver=false}catch(e){checks.xhrReceiver=e instanceof TypeError}
      let synchronous=false;const sync=new XMLHttpRequest();sync.open('GET','/blocked',false);sync.onload=()=>synchronous=true;sync.send();checks.xhrSync=synchronous
      for (const [key, previous] of Object.entries({storage:b.storage,permissions:b.permissions,
        mediaCapabilities:b.mediaCapabilities,plugins:b.plugins,mimeTypes:b.mimes})) {
        if(!pdfAvailable&&['plugins','mimeTypes'].includes(key)){try{n[key];checks[`identity-${key}`]=false}catch(e){checks[`identity-${key}`]=e.name==='SecurityError'}}
        else checks[`identity-${key}`] = n[key] === previous
      }
      checks.identityNotification = window.Notification.prototype === b.notification.prototype &&
        Notification.prototype.constructor === Notification
      checks.uaIdentity = (n.userAgentData === n.userAgentData) === b.uaStable &&
        Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgentData')?.get === b.uaGetter
      checks.plugins = !pdfAvailable || n.plugins instanceof PluginArray && !Array.isArray(n.plugins) &&
        n.mimeTypes instanceof MimeTypeArray && !Array.isArray(n.mimeTypes) &&
        PluginArray.prototype.item.call(n.plugins, '0') === (n.plugins[0] ?? null) && !('refresh' in n.mimeTypes)
      const voices = speechSynthesis.getVoices()
      checks.speech = speechSynthesis.getVoices !== b.getVoices && voices.every((voice, index) => {
        const utterance = new SpeechSynthesisUtterance(); utterance.voice = voice
        return utterance.voice === voice && voice instanceof SpeechSynthesisVoice &&
          voice.lang === 'en-US' && voice.localService && voice.name === `en-US Voice ${index + 1}` &&
          voice.voiceURI === `urn:voice:en-US:${index + 1}` && voice.default === (index === 0)
      })
      checks.speechBounded = voices.length <= 2 && voices.length <= b.getVoices.call(speechSynthesis).length
      const nativeVoices = b.getVoices.call(speechSynthesis)
      if(nativeVoices.length) checks.speechPopulated = voices.length > 0
      try { speechSynthesis.getVoices.call({}); checks.speechReceiver = false }
      catch(e) { checks.speechReceiver = e instanceof TypeError }
      const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent')
      checks.getter = descriptor.get.name === b.userAgent.get.name && descriptor.get.length === b.userAgent.get.length &&
        descriptor.configurable === b.userAgent.configurable && descriptor.enumerable === b.userAgent.enumerable &&
        !Object.hasOwn(descriptor.get, 'prototype')
      checks.cookieObservation = n.cookieEnabled === true
      try { descriptor.get.call({}); checks.receiver = false } catch (e) { checks.receiver = e instanceof TypeError }
      if (n.userAgentData) {
      const data = await n.userAgentData.getHighEntropyValues([])
      const mappings={architecture:'architecture',bitness:'bitness',model:'model',platformVersion:'platform_version',fullVersionList:'full_version_list',uaFullVersion:'ua_full_version',wow64:'wow64',formFactors:'form_factors'}
      checks.completeHints=true
      for(const [hint,key] of Object.entries(mappings)) {
        const value=await n.userAgentData.getHighEntropyValues([hint])
        if(hint in value&&JSON.stringify(value[hint])!==JSON.stringify(expectedProfile.ua_data[key]))checks.completeHints=false
        if(Object.keys(value).some(name=>!['brands','mobile','platform',hint].includes(name)))checks.completeHints=false
      }
      const all=await n.userAgentData.getHighEntropyValues(Object.keys(mappings))
      checks.hintTypes=!('formFactors' in all)||Array.isArray(all.formFactors)&&all.formFactors.every(value=>typeof value==='string')
      checks.hintBaseline=JSON.stringify(await n.userAgentData.getHighEntropyValues(['unknown-future-identity']))===JSON.stringify(data)
      checks.ua = n.userAgentData instanceof NavigatorUAData &&
        Object.hasOwn(data, 'brands') && Object.hasOwn(data, 'mobile') && Object.hasOwn(data, 'platform') &&
        Object.isFrozen(n.userAgentData.brands) && n.userAgentData.toJSON().brands[0].brand === n.userAgentData.brands[0].brand
      checks.brandMutability = Object.isFrozen(n.userAgentData.brands[0]) === b.brandRecordFrozen
      checks.brandArrayIdentity = (n.userAgentData.brands === n.userAgentData.brands) === b.brandsStable
      } else { checks.ua = !('userAgentData' in n) }
      try { await n.permissions.query({name:'static-not-a-permission'}); checks.permissions = false }
      catch (e) { checks.permissions = e instanceof TypeError }
      const status = await n.permissions.query({name:'camera'})
      let delivered = 0; status.onchange = () => delivered++
      EventTarget.prototype.dispatchEvent.call(status, new Event('change'))
      checks.permissionBrand = status instanceof PermissionStatus && delivered === 1
      checks.permissionMask = status.state === 'denied' &&
        Object.getOwnPropertyDescriptor(PermissionStatus.prototype,'state').get.call(status) === 'denied'
      let reads = 0
      const input = Object.freeze({get name(){ if(this !== input) throw new Error('descriptor receiver'); reads++; return {toString(){return 'camera'}} }})
      const maskedStatus = await n.permissions.query(input)
      const maskedReads = reads; reads = 0
      await b.query.call(n.permissions, input)
      checks.permissionConversion = maskedStatus.state === 'denied' && maskedReads === reads
      checks.notificationMask = Notification.permission === 'denied' && await Notification.requestPermission() === 'denied'
      const requestPermission = Notification.requestPermission
      checks.notificationBorrowing = await requestPermission() === 'denied' &&
        await requestPermission.call({}) === 'denied'
      try { new Notification('test-only denied notification'); checks.notificationDenial = false }
      catch(e) { checks.notificationDenial = e instanceof DOMException && e.name === 'NotAllowedError' }
      try { new Notification(Symbol()); checks.notificationConversion = false }
      catch(e) { checks.notificationConversion = e instanceof TypeError }
      try { await n.mediaCapabilities.decodingInfo({}); checks.codecValidation = false }
      catch (e) { checks.codecValidation = e instanceof TypeError }
      checks.codecSupport = !(await n.mediaCapabilities.decodingInfo({type:'file',video:{contentType:'video/x-static-invalid',
        width:640,height:480,bitrate:1000000,framerate:30}})).supported
      const codec = {type:'file',audio:{contentType:'audio/webm; codecs="opus"',channels:'2',bitrate:128000,samplerate:48000}}
      const capability = await n.mediaCapabilities.decodingInfo(codec)
      const nativeCapability = await b.decodingInfo.call(n.mediaCapabilities, codec)
       checks.codecMask = capability.supported === true &&
        capability.smooth === capability.supported && capability.powerEfficient === capability.supported &&
        capability.keySystemAccess === nativeCapability.keySystemAccess
      checks.storage = n.storage instanceof StorageManager &&
        await n.storage.persisted() === await b.storage.persisted() &&
        (!n.storage.getDirectory || await n.storage.getDirectory() instanceof FileSystemDirectoryHandle)
      const estimate = await n.storage.estimate()
      const nativeEstimate = await b.estimate.call(n.storage)
      checks.storageMask = estimate.quota === expectedProfile.storage_quota && estimate.usage === expectedProfile.storage_usage &&
        estimate.usage <= estimate.quota &&
        (!estimate.usageDetails || Object.keys(estimate.usageDetails).length === 0) && estimate !== nativeEstimate
      try { await n.storage.estimate.call({}); checks.storageReceiver = false }
      catch(e) { checks.storageReceiver = e instanceof TypeError }
      if(n.storage.getDirectory) {
        const directory=await n.storage.getDirectory(),name='profile-estimate-fixture'
        try {
          const file=await directory.getFileHandle(name,{create:true}),writer=await file.createWritable()
          await writer.write(new Uint8Array(4096));await writer.close()
          checks.storageWritesFixed=JSON.stringify(await n.storage.estimate())===JSON.stringify(estimate)
        } finally { await directory.removeEntry(name) }
      }
      checks.gamepads = Array.from(n.getGamepads()).every((pad) => pad === null)
      if(window.RTCPeerConnection){
        const left=new RTCPeerConnection(),right=new RTCPeerConnection()
        try{
          let listenerCalls=0
          const listener={handleEvent(event){listenerCalls++;if(event.candidate)right.addIceCandidate(event.candidate).catch(()=>{})}}
          left.addEventListener('icecandidate',listener)
          right.onicecandidate=event=>{if(event.candidate)left.addIceCandidate(event.candidate).catch(()=>{})}
          const channel=left.createDataChannel('local-fixture')
          const received=new Promise(resolve=>right.ondatachannel=event=>event.channel.onmessage=message=>resolve(message.data))
          const offer=await left.createOffer();await left.setLocalDescription(offer);await right.setRemoteDescription(offer)
          const answer=await right.createAnswer();await right.setLocalDescription(answer);await left.setRemoteDescription(answer)
          await Promise.race([new Promise(resolve=>{if(channel.readyState==='open')resolve();else channel.onopen=resolve}),new Promise((_,reject)=>setTimeout(()=>reject(Error('local peer timeout')),5000))])
          channel.send('privacy-fixture');checks.peerRoundTrip=await received==='privacy-fixture'&&listenerCalls>0
          const stats=await left.getStats(),entries=Array.from(stats.values())
          checks.statsAddresses=entries.every(value=>!['address','ip','ipAddress','relatedAddress'].some(key=>typeof value[key]==='string'&&value[key]&&!['192.0.2.1','2001:db8::1'].includes(value[key])))
          let callbackOK=true;stats.forEach((value,key)=>{if(value.address!==stats.get(key).address)callbackOK=false})
          checks.statsIteration=callbackOK&&Array.from(stats).length===stats.size&&stats[Symbol.iterator]===stats.entries
          left.removeEventListener('icecandidate',listener)
          try{Object.getOwnPropertyDescriptor(RTCPeerConnection.prototype,'onicecandidate').get.call({});checks.peerReceiver=false}
          catch(e){checks.peerReceiver=e instanceof TypeError}
        }finally{left.close();right.close()}
      }
      if (n.getBattery) {
      const batteryPromise = n.getBattery()
      const battery = await batteryPromise
      delivered = 0; battery.onlevelchange = () => delivered++
      EventTarget.prototype.dispatchEvent.call(battery, new Event('levelchange'))
      checks.battery = battery instanceof BatteryManager && n.getBattery() === batteryPromise && delivered === 1 && battery.level === 1
      } else { checks.battery = typeof n.getBattery === b.battery }
      const connection = n.connection
      if (connection) {
      delivered = 0; connection.onchange = () => delivered++
      EventTarget.prototype.dispatchEvent.call(connection, new Event('change'))
      checks.network = connection instanceof NetworkInformation && connection === n.connection && delivered === 1 && connection.saveData === false
      } else { checks.network = typeof n.connection === b.network }
      const stream = await n.mediaDevices.getUserMedia({audio:true,video:true})
      try {
        const devices = await n.mediaDevices.enumerateDevices()
        checks.devices = devices.every((device) => device instanceof MediaDeviceInfo &&
          device.toJSON().label === device.label && device.toJSON().deviceId === device.deviceId &&
          device.toJSON().groupId === device.groupId && !Object.isFrozen(device))
        checks.devicePrivacy = devices.every((device) => !device.deviceId || ['default','communications'].includes(device.deviceId) ||
          device.deviceId !== b.deviceId.call(device)) &&
          devices.every((device) => !device.groupId || device.groupId !== b.groupId.call(device)) &&
          ['audioinput','audiooutput','videoinput'].every((kind) => devices.filter((device)=>device.kind === kind).length <= 1)
        checks.inputCapabilities = devices.every((device) => {
          if (!device.getCapabilities) return true
          const caps=device.getCapabilities()
          const nativeCaps=b.deviceCaps.call(device)
          const check=(key)=>!caps[key] || key==='deviceId' && ['default','communications'].includes(nativeCaps[key]) &&
            caps[key]===nativeCaps[key] || caps[key]!==nativeCaps[key] &&
            (nativeCaps[key]!==b[key].call(device) || caps[key]===device[key])
          return check('deviceId') && check('groupId')
        })
        const video = devices.find((device) => device.kind === 'videoinput')
        const exact = await n.mediaDevices.getUserMedia({video:{deviceId:{exact:video.deviceId}}})
        checks.selection = exact.getVideoTracks()[0].getSettings().deviceId === video.deviceId
        await exact.getVideoTracks()[0].applyConstraints({deviceId:{exact:video.deviceId}})
        checks.applyConstraints = exact.getVideoTracks()[0].getSettings().deviceId === video.deviceId
        const advanced = {advanced:[{deviceId:{exact:video.deviceId},groupId:{ideal:video.groupId}}]}
        await exact.getVideoTracks()[0].applyConstraints(advanced)
        const roundTrip = exact.getVideoTracks()[0].getConstraints()
        const selectedId = (value) => typeof value === 'string' ? value : value?.exact ?? value?.ideal
        const serializedConstraints = JSON.stringify(roundTrip)
        checks.advancedAliases = selectedId(roundTrip.advanced?.[0].deviceId) === video.deviceId &&
          selectedId(roundTrip.advanced[0].groupId) === video.groupId &&
          !serializedConstraints.includes(b.deviceId.call(video)) &&
          !serializedConstraints.includes(b.groupId.call(video))
        exact.getTracks().forEach((track) => track.stop())
        try { await MediaDevices.prototype.enumerateDevices.call({}); checks.mediaReceiver = false }
        catch (e) { checks.mediaReceiver = e instanceof TypeError }
      } finally { stream.getTracks().forEach((track) => track.stop()) }
      if(window.AudioContext) {
        let optionReads=0
        const options={get sampleRate(){if(this!==options)throw new Error('audio options receiver');optionReads++;return 44100}}
        class CustomAudio extends AudioContext {}
        const context=new CustomAudio(options)
        checks.audioConstructor = context instanceof AudioContext && context instanceof CustomAudio &&
          AudioContext.prototype.constructor===AudioContext && optionReads===1
        checks.audioExplicitRate=context.sampleRate===expectedProfile.audio_context.sample_rate&&b.audioRate.call(context)===44100
        const analyser=context.createAnalyser(),large=new Float32Array(analyser.frequencyBinCount+8);large.fill(123)
        analyser.getFloatFrequencyData(large);checks.analyserTail=Array.from(large.slice(analyser.frequencyBinCount)).every(value=>value===123)
        const oscillator=context.createOscillator();oscillator.frequency.value=777;oscillator.start();oscillator.frequency.setValueAtTime(880,context.currentTime+.01);checks.oscillatorControl=oscillator.frequency instanceof AudioParam;oscillator.stop()
        await context.close()
      }
      const gl = document.createElement('canvas').getContext('webgl2')
      if (gl) {
        checks.webgl = gl instanceof WebGL2RenderingContext && gl.getParameter === gl.getParameter &&
          WebGL2RenderingContext.prototype.getParameter.call(gl, gl.MAX_VIEWPORT_DIMS) instanceof Int32Array &&
          gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE) instanceof Float32Array &&
          gl.getParameter(gl.VERSION).includes('WebGL 2')
        const policy=expectedProfile.webgl_contexts.webgl2
        checks.gpuProfileMetadata=gl.getParameter(gl.VERSION)===policy.version&&
          gl.getParameter(gl.VENDOR)===policy.vendor&&gl.getParameter(gl.RENDERER)===policy.renderer&&
          gl.getParameter(gl.MAX_TEXTURE_SIZE)===policy.parameters.MAX_TEXTURE_SIZE&&
          JSON.stringify(gl.getSupportedExtensions())===JSON.stringify(policy.extensions)
        let conversions=0
        gl.getParameter({valueOf(){ conversions++; return gl.MAX_TEXTURE_SIZE }})
        checks.glConversion = conversions === 1
      }
      const frame = document.createElement('iframe'); document.body.append(frame)
      checks.syncFrame = frame.contentWindow.navigator.userAgent === n.userAgent &&
        frame.contentWindow.CanvasRenderingContext2D.prototype.getImageData !== CanvasRenderingContext2D.prototype.getImageData
      checks.timezone = new Intl.DateTimeFormat('en-US', {timeZone:'UTC'}).resolvedOptions().timeZone === 'UTC' &&
        new Intl.DateTimeFormat() instanceof Intl.DateTimeFormat && new Intl.DateTimeFormat().constructor === Intl.DateTimeFormat &&
        Number.isNaN(new Date(NaN).getTimezoneOffset()) &&
        new Date('2026-01-15T12:00:00Z').getTimezoneOffset() === expectedOffsets[0] &&
        new Date('2026-07-15T12:00:00Z').getTimezoneOffset() === expectedOffsets[1]
      let optionReads = 0
      const options = { get timeZone() { if (this !== options) throw new Error('changed options receiver'); optionReads++; return 'UTC' } }
      checks.zoneOptions = new Intl.DateTimeFormat('en-US', options).resolvedOptions().timeZone === 'UTC' && optionReads === 1
      const clock = Array.from({length:1000}, () => performance.now())
      checks.monotonic = clock.every((value, i) => i === 0 || value >= clock[i-1])
      try { Performance.prototype.now.call({}); checks.clockReceiver=false } catch(e) { checks.clockReceiver=e instanceof TypeError }
      const entries = performance.getEntries()
      checks.entries = entries.every((entry) => entry instanceof PerformanceEntry)
      const stable = performance.mark('static-fixture-stable')
      checks.entrySerialization = PerformanceEntry.prototype.toJSON.call(stable).startTime === stable.startTime &&
        stable.toJSON().duration === stable.duration
      const timingKeys = ['startTime','duration','fetchStart','domainLookupStart','domainLookupEnd','connectStart',
        'connectEnd','secureConnectionStart','requestStart','responseStart','responseEnd','workerStart']
      checks.resourceTiming = performance.getEntriesByType('resource').every((entry) => {
        const json = entry.toJSON()
        return timingKeys.every((key) => !(key in json) ||
          json[key] === entry[key] && Math.abs(entry[key]*10-Math.round(entry[key]*10)) < 0.00001)
      })
      return checks
    })
    if(!shapes.installation) console.log(await page.evaluate(()=>window.__fixtureReport))
    for (const [name, value] of Object.entries(shapes)) assert.equal(value, true, name)
    console.log(`PASS: ${Object.keys(shapes).length} native interface/receiver/functionality checks on ${browser.version()}`)

    const workers = await page.evaluate(async () => {
      const run = (url, options) => new Promise((resolve, reject) => {
        const worker = new Worker(url, options)
        worker.onmessage = (e) => { worker.terminate(); resolve(e.data) }; worker.onerror = reject
      })
      const classic = await run('./classic.js')
      const module = await run('./module.js', {type:'module'})
      const shared = async () => {
        const worker = new SharedWorker('./shared.js', 'native-sharing')
        const data = await new Promise((resolve) => { worker.port.onmessage = (e) => resolve(e.data) })
        return { worker, data }
      }
      const a = await shared(), b = await shared()
      a.worker.port.close(); b.worker.port.close()
      const services = []
      for (const [url, type] of [['./service.js','classic'], ['./service-module.js','module']]) {
        const registration = await navigator.serviceWorker.register(url, {type})
        let worker = registration.installing || registration.waiting || registration.active
        if (worker.state !== 'activated') await new Promise((resolve) => worker.addEventListener('statechange', () => {
          if (worker.state === 'activated') resolve()
        }))
        const channel = new MessageChannel()
        const data = new Promise((resolve) => { channel.port1.onmessage = (event) => resolve(event.data) })
        worker.postMessage('inspect', [channel.port2]); services.push(await data)
        await registration.unregister(); channel.port1.close()
      }
      return {classic, module, shared:[a.data,b.data], services}
    })
    const ua = raw.fingerprint.user_agent
    assert.equal(workers.classic.ua, ua); assert.equal(workers.classic.helper, ua); assert.equal(workers.classic.strict, true)
    assert.equal(workers.classic.href, `${origin}/classic.js`)
    assert.equal(workers.module.ua, ua); assert.equal(workers.module.dependency, ua)
    assert.equal(workers.module.href, `${origin}/module.js`)
    assert.deepEqual(workers.shared.map((value) => value.count), [1,2])
    for (const worker of [...workers.shared, ...workers.services]) assert.equal(worker.ua, ua)
    assert.equal(workers.services[1].dependency, ua)
    assert.equal(workers.services[0].href, `${origin}/service.js`)
    assert.equal(workers.services[1].href, `${origin}/service-module.js`)
    for (const worker of [workers.classic,workers.module,...workers.shared,...workers.services]) {
      const privacy = worker.privacy
      if (privacy.storage) {
        assert.equal(privacy.storage.quota,107374182400)
        assert.equal(privacy.storage.usage,raw.fingerprint.storage_usage)
        assert.ok(!privacy.storage.usageDetails || Object.keys(privacy.storage.usageDetails).length === 0)
      }
      if (privacy.notification) assert.equal(privacy.notification,'denied')
      if (privacy.permission) assert.equal(privacy.permission,'denied')
      if (privacy.media) {
        assert.equal(privacy.media.smooth,privacy.media.supported)
        assert.equal(privacy.media.powerEfficient,privacy.media.supported)
      }
      if (privacy.canvas) {
        assert.equal(privacy.canvas.changed,true)
        assert.equal(privacy.canvas.repeated,true)
        assert.ok(privacy.canvas.blob>0)
      }
    }
    for (const file of ['classic.js','shared.js','service.js']) {
      assert.equal(observations.find((entry) => entry.pathname === `/${file}`).mode, 'same-origin', file)
    }
    for (const file of ['module.js','service-module.js']) {
      assert.ok(['same-origin','cors'].includes(observations.find((entry) => entry.pathname === `/${file}`).mode), file)
    }
    assert.deepEqual(errors, [])
    console.log('PASS: Rust-produced classic/module/shared/service worker bootstraps, dependency timing, URL bases, sharing and strict mode')
  } finally {
    await browser.close(); await new Promise((resolve) => server.close(resolve))
  }
}
main().catch((error) => { console.error(error); server.close(); process.exitCode = 1 })

