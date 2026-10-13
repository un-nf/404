import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { findDescriptor, replaceMethod, replaceGetter } from '../core/descriptors.js'
import { resolveWebGLParameters } from '../core/webgl-parameters.js'
export { resolveWebGLParameter } from '../core/webgl-parameters.js'

export function installWebGLSpoof() {
  const fp=getFingerprint(), precisionValues=new WeakMap()
  // Resolve every declaration before mutating any host descriptor. Extension
  // constants are not context-prototype properties.
  const configured=resolveWebGLParameters(fp)
  let installed=0
  for(const [kind,proto] of [['webgl1',globalThis.WebGLRenderingContext?.prototype],['webgl2',globalThis.WebGL2RenderingContext?.prototype]]) {
    if(!proto)continue
    const record=fp.webgl_contexts?.[kind]
    if(!record)throw new TypeError(`STATIC missing ${kind} observation policy`)
    const validate=findDescriptor(proto,'getContextAttributes')?.descriptor.value
    if(!validate)continue
    const overrides=new Map([[0x1f00,record.vendor],[0x1f01,record.renderer],[0x1f02,record.version],
      [0x8b8c,record.shading_language_version],[0x9245,record.debug_vendor],[0x9246,record.debug_renderer]])
    for(const [key,value] of configured.get(kind))overrides.set(key,value)
    installed+=Number(replaceMethod(proto,'getParameter',(native,receiver,args)=>{
      if(!args.length)return Reflect.apply(native,receiver,args)
      Reflect.apply(validate,receiver,[])
      const key=(+args[0])>>>0,value=Reflect.apply(native,receiver,[key,...args.slice(1)])
      // Native invalid-enum/context-loss/extension validation still applies.
      if(value===null||!overrides.has(key))return value
      const configured=overrides.get(key)
      if(ArrayBuffer.isView(value))return new value.constructor(configured)
      return configured
    }))
    replaceMethod(proto,'getSupportedExtensions',(native,receiver,args)=>{
      const value=Reflect.apply(native,receiver,args)
      return value===null?null:record.extensions.slice()
    })
    replaceMethod(proto,'getExtension',(native,receiver,args)=>{
      if(!args.length)return Reflect.apply(native,receiver,args)
      Reflect.apply(validate,receiver,[])
      const name=`${args[0]}`
      // A reported inventory creates no missing implementation or GPU feature.
      if(!record.extensions.some(value=>value.toLowerCase()===name.toLowerCase()))return null
      return Reflect.apply(native,receiver,[name,...args.slice(1)])
    })
    replaceMethod(proto,'getShaderPrecisionFormat',(native,receiver,args)=>{
      if(args.length<2)return Reflect.apply(native,receiver,args)
      Reflect.apply(validate,receiver,[])
      const shader=(+args[0])>>>0,precision=(+args[1])>>>0
      const value=Reflect.apply(native,receiver,[shader,precision,...args.slice(2)])
      const configured=record.shader_precision[`${shader}:${precision}`]
      if(value&&configured)precisionValues.set(value,configured)
      return value
    })
  }
  for(const key of ['rangeMin','rangeMax','precision'])replaceGetter(globalThis.WebGLShaderPrecisionFormat?.prototype,key,
    (native,receiver)=>precisionValues.get(receiver)?.[key]??native)
  markModule('webgl',{status:installed?'partial':'unavailable',detail:'selected per-version metadata, exact limits, extension inventory and configured precision; actual extensions/allocations/rendering/timing remain operational exposure'})
}
