import { getRuntime, markModule } from '../core/guard.js'
import { findDescriptor, replaceGetter, replaceMethod } from '../core/descriptors.js'
const DEFAULT_RULES=[{hostSuffix:'play.google.com',pathPrefix:'/log'}]
export function matchesPrivacyRule(url,rules,base){
  try{const parsed=new URL(url,base);return rules.some(rule=>(!rule.hostSuffix||parsed.hostname===rule.hostSuffix||parsed.hostname.endsWith('.'+rule.hostSuffix))&&(!rule.pathPrefix||parsed.pathname.startsWith(rule.pathPrefix)))}catch{return false}
}
export function installBeaconBlackhole(){
  const runtime=getRuntime(),rules=DEFAULT_RULES.concat(runtime.config.raw.privacy_rules||[])
  const base=()=>document.baseURI,Request=runtime.nativeRefs.request,Response=runtime.nativeRefs.response
  if(runtime.nativeRefs.fetch)replaceMethod(window,'fetch',(native,receiver,args)=>{
    if(!args.length)return Reflect.apply(native,receiver,args)
    let request
    try{request=new Request(args[0],args[1])}catch(error){return Promise.reject(error)}
    if(request.signal.aborted)return Promise.reject(request.signal.reason)
    if(matchesPrivacyRule(request.url,rules,base()))return Promise.resolve(new Response(null,{status:204}))
    return Reflect.apply(native,receiver,[request])
  })
  const navigatorBrand=findDescriptor(runtime.nativeRefs.NavigatorPrototype,'userAgent')?.descriptor.get
  if(runtime.nativeRefs.sendBeacon)replaceMethod(runtime.nativeRefs.NavigatorPrototype,'sendBeacon',(native,receiver,args)=>{
    if(!args.length)return Reflect.apply(native,receiver,args)
    if(navigatorBrand)Reflect.apply(navigatorBrand,receiver,[])
    const url=new URL(`${args[0]}`,base()).href
    if(!matchesPrivacyRule(url,rules,base()))return Reflect.apply(native,receiver,[url,...args.slice(1)])
    const data=args[1],bytes=typeof data==='string'?new TextEncoder().encode(data).byteLength:data?.size??data?.byteLength??0
    return bytes<=65536
  })
  const prototype=runtime.nativeRefs.xhrPrototype
  if(prototype&&runtime.nativeRefs.xhrOpen&&runtime.nativeRefs.xhrSend){
    const state=new WeakMap(),brand=findDescriptor(prototype,'readyState').descriptor.get
    const fire=(xhr,type)=>xhr.dispatchEvent(new Event(type))
    for(const key of ['readyState','status','statusText','responseURL','responseText','response'])replaceGetter(prototype,key,(native,xhr)=>{
      const record=state.get(xhr)
      if(!record?.blocked)return native
      if(key==='readyState')return record.done?4:1
      if(!record.done)return native
      if(key==='status')return 204
      if(key==='statusText')return 'No Content'
      if(key==='responseURL')return record.url
      if(key==='responseText')return ''
      if(key==='response')return xhr.responseType==='json'||xhr.responseType==='document'?null:
        xhr.responseType==='arraybuffer'?(record.buffer??=new ArrayBuffer(0)):xhr.responseType==='blob'?(record.blob??=new Blob([])):''
      return native
    })
    replaceMethod(prototype,'open',(native,receiver,args)=>{
      if(args.length<2)return Reflect.apply(native,receiver,args)
      Reflect.apply(brand,receiver,[]);state.delete(receiver)
      let url
      const captured={ [Symbol.toPrimitive](){url=new URL(`${args[1]}`,base()).href;return url} }
      const result=Reflect.apply(native,receiver,[args[0],captured,...args.slice(2)])
      state.set(receiver,{url,async:args.length<3||args[2]===undefined?true:Boolean(args[2]),blocked:false,done:false,sent:false,cancelled:false})
      return result
    })
    replaceMethod(prototype,'send',(native,receiver,args)=>{
      const nativeState=Reflect.apply(brand,receiver,[]),record=state.get(receiver)
      if(!record||!matchesPrivacyRule(record.url,rules,base()))return Reflect.apply(native,receiver,args)
      if(nativeState!==1||record.sent)throw new DOMException('XMLHttpRequest is not OPENED','InvalidStateError')
      record.blocked=true;record.sent=true
      const finish=()=>{if(record.cancelled||state.get(receiver)!==record)return;fire(receiver,'loadstart');record.done=true;fire(receiver,'readystatechange');fire(receiver,'load');fire(receiver,'loadend')}
      if(record.async)setTimeout(finish,0);else finish()
      return undefined
    })
    replaceMethod(prototype,'abort',(native,receiver,args)=>{
      const record=state.get(receiver),pending=record?.blocked&&!record.done
      if(record)record.cancelled=true
      state.delete(receiver)
      const result=Reflect.apply(native,receiver,args)
      if(pending){fire(receiver,'abort');fire(receiver,'loadend')}
      return result
    })
  }
  markModule('beaconBlackhole',{status:'partial',detail:'validated fetch/abort, exact domain boundaries, native methods/receiver metadata, virtual XHR response/lifecycle without own fake slots; synthetic event trust/body-conversion limits remain explicit'})
}
