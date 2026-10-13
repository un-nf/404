import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { replaceMethod } from '../core/descriptors.js'

const mimeKey=value=>String(value||'').toLowerCase().replace(/[\s"]/g,'')
export function mediaTypeSupported(type, fp) {
  const policy=fp.media_capabilities || {}
  const key=mimeKey(type)
  return [...(policy.audio_content_types||[]),...(policy.video_content_types||[])].some(value=>mimeKey(value)===key)
}

export function mediaConfigurationSupported(configuration, fp, operation='decoding') {
  const policy=fp.media_capabilities || {}
  if(!configuration || !(policy[operation+'_types']||[]).includes(configuration.type))return false
  if(configuration.keySystemConfiguration && !(policy.key_systems||[]).includes(configuration.keySystemConfiguration.keySystem))return false
  if(!configuration.audio && !configuration.video)return false
  for(const kind of ['audio','video']){
    const track=configuration[kind];if(!track)continue
    if(!(policy[kind+'_content_types']||[]).some(value=>mimeKey(value)===mimeKey(track.contentType)))return false
    for(const [field,limit] of Object.entries({width:'max_width',height:'max_height',bitrate:'max_bitrate',framerate:'max_framerate',samplerate:'max_sample_rate',channels:'max_channels'})){
      if(track[field]!==undefined && (!Number.isFinite(Number(track[field])) || Number(track[field])>(policy[limit]??0)))return false
    }
    // Optional advanced decoder properties are not silently delegated to the host.
    if(track.spatialRendering || track.hdrMetadataType || track.colorGamut && track.colorGamut!=='srgb' || track.transferFunction && track.transferFunction!=='srgb' || track.scalabilityMode || track.spatialScalability)return false
  }
  return true
}

export function normalizeMediaCapability(result, fp, operation='decoding') {
  const supported=mediaConfigurationSupported(result.configuration,fp,operation)
  // This is an advertised support policy, not a codec/DRM implementation.
  // Genuine validation, playback failures and DRM handles remain operational.
  return { ...result, supported,
    smooth: supported && (fp.media_capabilities?.smooth ?? true),
    powerEfficient: supported && (fp.media_capabilities?.power_efficient ?? true),
    ...('keySystemAccess' in result ? {keySystemAccess:supported?result.keySystemAccess:null}:{}) }
}

export function installMediaCapabilities() {
  const capabilities = navigator.mediaCapabilities
  const fp = getFingerprint()
  let installed = 0
  for (const key of ['decodingInfo', 'encodingInfo']) {
    if(!capabilities)continue
    installed += Number(replaceMethod(capabilities, key, (native,receiver,args) => {
      const snapshot={}
      function dictionary(input,output){
        if(!input || !['object','function'].includes(typeof input))return input
        return new Proxy({}, {get(_target,field){
          const value=Reflect.get(input,field,input)
          if(['audio','video','keySystemConfiguration'].includes(field)){
            output[field]=value&&typeof value==='object'?{}:value
            return dictionary(value,output[field])
          }
          output[field]=value
          if(value&&['object','function'].includes(typeof value))return { [Symbol.toPrimitive](hint){
            const converted=hint==='string'?`${value}`:+value
            output[field]=converted;return converted
          }}
          return value
        }})
      }
      const forwarded=args.slice();if(args.length)forwarded[0]=dictionary(args[0],snapshot)
      return Reflect.apply(native,receiver,forwarded).then(result=>normalizeMediaCapability(
        {...result,configuration:result.configuration??snapshot},fp,key==='decodingInfo'?'decoding':'encoding'))
    }))
  }
  for(const [target,key,kind] of [[globalThis.HTMLMediaElement?.prototype,'canPlayType','element'],[globalThis.MediaSource,'isTypeSupported','source']]){
    if(!target)continue
    installed+=Number(replaceMethod(target,key,(native,receiver,args)=>{
      if(!args.length)return Reflect.apply(native,receiver,args)
      let converted
      const facade={ [Symbol.toPrimitive](){if(typeof args[0]==='symbol')throw new TypeError('Cannot convert Symbol to string');converted=String(args[0]);return converted} }
      Reflect.apply(native,receiver,[facade,...args.slice(1)])
      const supported=mediaTypeSupported(converted,fp) && (kind!=='source'||(fp.media_capabilities?.decoding_types||[]).includes('media-source'))
      return kind==='element'?(supported?'probably':''):supported
    }))
  }
  markModule('mediaCapabilities', { status: installed ? 'partial' : 'unavailable',
    detail: 'deterministic profile matrix for media capabilities, element and MediaSource probes; genuine validation/operations; WebCodecs/RTP/DRM and absent interfaces remain partial' })
}
