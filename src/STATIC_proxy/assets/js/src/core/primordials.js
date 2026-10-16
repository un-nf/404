// Capture before application execution. These bindings are private to each
// realm bundle; page built-ins remain writable. This cannot trust an intrinsic
// that was already replaced before bootstrap (see the realm coverage contract).
import { currentLifetime, withinLifetime } from './lifetimes.js';
const Symbol=globalThis.Symbol;
const apply = Reflect.apply
const construct = Reflect.construct
const get = Reflect.get
const define = Object.defineProperty
const descriptors = Object.getOwnPropertyDescriptors
const ownKeys = Reflect.ownKeys
const freeze = Object.freeze
const create = Object.create, assign = Object.assign
const NativeProxy = Proxy
const functionPrototype = Function.prototype
const uncurry = fn => (receiver, ...args) => apply(fn, receiver, args)
const arrayIterator=Array.prototype[Symbol.iterator],arrayNext=Object.getPrototypeOf([][Symbol.iterator]()).next,isArray=Array.isArray
const protectedArrays=new WeakSet(),weakHas=WeakSet.prototype.has,weakAdd=WeakSet.prototype.add,isFrozen=Object.isFrozen
function privateIterator(iterator,next,entries=false) {
  const result=create(null)
  result.next=(...args)=>{const step=apply(next,iterator,args);if(!step.done&&entries&&isArray(step.value))step.value=protectArray(step.value);return step}
  result[Symbol.iterator]=function(){return this}
  return result
}
function protectArray(array) {
  if(apply(weakHas,protectedArrays,[array]))return array;
  if(isFrozen(array)){const output=[];output.length=array.length;for(let index=0;index<array.length;index++)if(index in array)put(output,index,array[index]);array=output;}
  const descriptor=create(null);descriptor.value=function(){return privateIterator(apply(arrayIterator,this,[]),arrayNext,false)};descriptor.configurable=true
  define(array,Symbol.iterator,descriptor);apply(weakAdd,protectedArrays,[array]);return array
}

function staticFacade(native) {
  const facade = function (...args) { return new.target ? construct(native,args,new.target===facade?native:new.target) : apply(native,undefined,args) }
  for (const key of ownKeys(native)) {
    if (key === 'name' || key === 'length' || key === 'prototype') continue
    const descriptor=Object.getOwnPropertyDescriptor(native,key)
    if(native===Object&&(key==='entries'||key==='keys'||key==='values')){const method=descriptor.value;descriptor.value=(...args)=>{
      const result=protectArray(apply(method,native,args));
      if(key==='entries'){const d=create(null);d.value=function(){return privateIterator(apply(arrayIterator,this,[]),arrayNext,true)};d.configurable=true;define(result,Symbol.iterator,d);}
      return result;
    }}
    define(facade, key, descriptor)
  }
  if (native.prototype) define(facade, 'prototype', {
    value: freeze(Object.create(null, descriptors(native.prototype)))
  })
  return freeze(facade)
}

export const ObjectIntrinsic = staticFacade(Object)
export const ReflectIntrinsic = freeze(Object.create(null, descriptors(Reflect)))
export const ArrayIntrinsic = staticFacade(Array)
export const JSONIntrinsic = freeze({ parse: JSON.parse, stringify: JSON.stringify })
const NativePromise = Promise
const resolve = Promise.resolve, reject = Promise.reject
export const PromiseIntrinsic = freeze({
  resolve: value => apply(resolve, NativePromise, [value]),
  reject: reason => apply(reject, NativePromise, [reason])
})
export const MathIntrinsic = freeze(Object.create(null, descriptors(Math)))
export const NumberIntrinsic = staticFacade(Number)
export const StringIntrinsic = staticFacade(String)
export const BooleanIntrinsic = Boolean
export const TypeErrorIntrinsic = TypeError
export const ProxyIntrinsic = NativeProxy
export const functionToString = Function.prototype.toString
export const FunctionPrototype = functionPrototype
export const NativeMapPrototype = Map.prototype
export const call = (fn, receiver, ...args) => apply(fn, receiver, args)
export const invoke = (fn, receiver, args) => apply(fn, receiver, args)
export const bind = (fn, receiver, ...args) => {const values=[receiver];for(let index=0;index<args.length;index++)put(values,index+1,args[index]);return apply(FunctionBind,fn,values)}
const FunctionBind = Function.prototype.bind

// A private map has its own captured operations. Its prototype and iterators
// never dispatch through a later page replacement of Map/WeakMap/Set methods.
function safeCollection(Native) {
  class Safe extends Native {constructor(input){super(input===undefined?undefined:Native===NativeMap?iterateEntries(input):iterate(input));}}
  for (const key of ownKeys(Native.prototype)) {
    if (key === 'constructor') continue
    const descriptor = Object.getOwnPropertyDescriptor(Native.prototype, key)
    if (typeof descriptor.value === 'function') {
      const method = descriptor.value
      if (key === 'entries' || key === 'keys' || key === 'values' || key === Symbol.iterator) {
        const probe = apply(method, new Native(), [])
        const next = Object.getPrototypeOf(probe).next
        descriptor.value = function (...args) {
          const iterator = apply(method, this, args)
          return privateIterator(iterator,next,key==='entries'||key===Symbol.iterator)
        }
      } else descriptor.value = function (...args) { return apply(method, this, args) }
    }
    define(Safe.prototype, key, descriptor)
  }
  freeze(Safe.prototype)
  return Safe
}
const NativeMap=Map;
export const MapIntrinsic = safeCollection(Map)
export const WeakMapIntrinsic = safeCollection(WeakMap)
export const SetIntrinsic = safeCollection(Set)
export const WeakSetIntrinsic = safeCollection(WeakSet)
const nativeThen = Promise.prototype.then
const ownDescriptor = Object.getOwnPropertyDescriptor
const deleteProperty = Reflect.deleteProperty
function InternalPromise(executor) { return new NativePromise(executor) }
define(InternalPromise, Symbol.species, {value:InternalPromise})
freeze(InternalPromise)
export function promiseThen(promise, fulfilled, rejected) {
  const live=currentLifetime();
  const callback=fn=>typeof fn==='function'?value=>withinLifetime(live,()=>apply(fn,undefined,[value])):fn;
  // A page-controlled Promise.prototype.constructor/species getter must never
  // receive the private pre-normalization promise. The promise is not exposed
  // yet; restore its shape before returning a genuine normalized promise.
  const previous = ownDescriptor(promise, 'constructor')
  const descriptor = create(null)
  descriptor.value=InternalPromise;descriptor.configurable=true
  define(promise,'constructor',descriptor)
  try { return apply(nativeThen,promise,[callback(fulfilled),callback(rejected)]) }
  finally { if(previous)define(promise,'constructor',assign(create(null),previous));else deleteProperty(promise,'constructor') }
}
export const promiseCatch = (promise, rejected) => promiseThen(promise, undefined, rejected)
const maximum=Math.max, minimum=Math.min, floor=Math.floor, ceil=Math.ceil
const integer=value=>{const number=NumberIntrinsic(value);return number!==number?0:number<0?ceil(number):floor(number)}
function put(array,index,value) { const d=create(null);d.value=value;d.writable=true;d.enumerable=true;d.configurable=true;define(array,index,d) }
export function arrayMap(array, callback, receiver) {
  const length=array.length,output=[];output.length=length
  for(let index=0;index<length;index++)if(index in array)put(output,index,apply(callback,receiver,[array[index],index,array]))
  return protectArray(output)
}
export function arrayFilter(array, callback, receiver) {
  const length=array.length,output=[]
  for(let index=0;index<length;index++)if(index in array){const value=array[index];if(apply(callback,receiver,[value,index,array]))put(output,output.length,value)}
  return protectArray(output)
}
export function arraySlice(array,start=0,end=array.length) {
  const length=array.length,first=integer(start),last=integer(end),lower=first<0?maximum(length+first,0):minimum(first,length),upper=last<0?maximum(length+last,0):minimum(last,length)
  const output=[];output.length=maximum(upper-lower,0)
  for(let index=lower;index<upper;index++)if(index in array)put(output,index-lower,array[index])
  return protectArray(output)
}
// Internal arrays own a saved iterator. Do not add that private bookkeeping
// property to a sequence/FrozenArray exposed by a browser API.
export function publicArray(array) {
  const output=[];output.length=array.length;
  for(let index=0;index<array.length;index++)if(index in array){const item=array[index];put(output,index,isArray(item)&&apply(weakHas,protectedArrays,[item])?publicArray(item):item);}
  return isFrozen(array)?freeze(output):output;
}
export const arraySome = uncurry(Array.prototype.some)
export const arrayEvery = uncurry(Array.prototype.every)
export const arrayFind = uncurry(Array.prototype.find)
export const arrayPush = (array,...items)=>{const start=array.length;for(let index=0;index<items.length;index++)put(array,start+index,items[index]);return array.length}
export const arrayReverse = uncurry(Array.prototype.reverse)
export const arrayJoin = uncurry(Array.prototype.join)
export const arrayIncludes = uncurry(Array.prototype.includes)
export const arrayForEach = uncurry(Array.prototype.forEach)
export const stringSlice = uncurry(String.prototype.slice)
const nativeSplit = String.prototype.split, nativeReplace=String.prototype.replace
const NativeRegExp = RegExp, nativeExec=RegExp.prototype.exec
const regexpSource=Object.getOwnPropertyDescriptor(RegExp.prototype,'source').get
const flagNames=['hasIndices','global','ignoreCase','multiline','dotAll','unicode','unicodeSets','sticky'],flagLetters=['d','g','i','m','s','u','v','y']
const flagGetters=[]
for(let index=0;index<flagNames.length;index++)flagGetters[index]=Object.getOwnPropertyDescriptor(RegExp.prototype,flagNames[index])?.get
function InternalRegExp(pattern, flags) { return protectRegExp(new NativeRegExp(pattern,flags)) }
define(InternalRegExp,Symbol.species,{value:InternalRegExp});freeze(InternalRegExp)
function protectRegExp(copy) {
  const keys=['exec','constructor',Symbol.split,Symbol.replace],values=[nativeExec,InternalRegExp,RegExpSplit,RegExpReplace]
  for(let index=0;index<keys.length;index++){const d=create(null);d.value=values[index];define(copy,keys[index],d)}
  return copy
}
const RegExpSplit=RegExp.prototype[Symbol.split],RegExpReplace=RegExp.prototype[Symbol.replace]
function expression(pattern) {
  let source
  try{source=apply(regexpSource,pattern,[])}catch{return pattern}
  let flags=''
  for(let index=0;index<flagGetters.length;index++)if(flagGetters[index]&&apply(flagGetters[index],pattern,[]))flags+=flagLetters[index]
  const copy=protectRegExp(new NativeRegExp(source,flags));copy.lastIndex=pattern.lastIndex;return copy
}
export const stringSplit=(value,pattern,limit)=>apply(nativeSplit,value,[expression(pattern),limit])
export const stringTrim = uncurry(String.prototype.trim)
export const stringStartsWith = uncurry(String.prototype.startsWith)
export const stringEndsWith = uncurry(String.prototype.endsWith)
export const stringReplace=(value,pattern,replacement)=>apply(nativeReplace,value,[expression(pattern),replacement])
export const regexpTest=(pattern,value)=>apply(nativeExec,expression(pattern),[value])!==null
export const stringIncludes = uncurry(String.prototype.includes)
export const stringLower = uncurry(String.prototype.toLowerCase)
export const stringCharCodeAt = uncurry(String.prototype.charCodeAt)
export const stringPadStart = uncurry(String.prototype.padStart)
export const numberString = uncurry(Number.prototype.toString)
export const slice = (value, ...args) => typeof value === 'string' ? stringSlice(value, ...args) : arraySlice(value, ...args)
export const includes = (value, ...args) => typeof value === 'string' ? stringIncludes(value, ...args) : arrayIncludes(value, ...args)
export const clone = globalThis.structuredClone
export const ArrayBufferIntrinsic = staticFacade(ArrayBuffer)
export const Uint8ArrayIntrinsic = Uint8Array
export const Uint32ArrayIntrinsic = Uint32Array
export const Int32ArrayIntrinsic = Int32Array
export const Float32ArrayIntrinsic = Float32Array
export const Float64ArrayIntrinsic = Float64Array
const typedPrototype = Object.getPrototypeOf(Uint8Array.prototype)
export const typedLength = uncurry(Object.getOwnPropertyDescriptor(typedPrototype,'length').get)
export const typedKind = uncurry(Object.getOwnPropertyDescriptor(typedPrototype,Symbol.toStringTag).get)
export const typedSet = uncurry(typedPrototype.set)
export const schedule = globalThis.setTimeout
export const cancel = globalThis.clearTimeout
const nativeRandom=globalThis.crypto?.getRandomValues,cryptoReceiver=globalThis.crypto
export const randomValues=nativeRandom ? value=>apply(nativeRandom,cryptoReceiver,[value]) : undefined
export const dateNow=Date.now
export const SymbolIntrinsic=Symbol;
const NativeURL=globalThis.URL,urlPrototype=NativeURL?.prototype,urlFields=create(null);
for(const key of ['href','hostname','pathname','origin'])urlFields[key]=urlPrototype&&Object.getOwnPropertyDescriptor(urlPrototype,key)?.get;
export function urlRecord(value,base){const parsed=new NativeURL(value,base),result=create(null);for(let index=0,keys=['href','hostname','pathname','origin'];index<keys.length;index++){const key=keys[index];result[key]=apply(urlFields[key],parsed,[]);}return result;}
const isView=ArrayBuffer.isView,typedValues=Object.getPrototypeOf(Uint8Array.prototype).values;
const stringIterator=String.prototype[Symbol.iterator],stringNext=Object.getPrototypeOf(''[Symbol.iterator]()).next;
export function iterate(value){
  let iterator,next;
  if(isArray(value)){iterator=apply(arrayIterator,value,[]);next=arrayNext;}
  else if(isView(value)){iterator=apply(typedValues,value,[]);next=arrayNext;}
  else if(typeof value==='string'){iterator=apply(stringIterator,value,[]);next=stringNext;}
  else return value;
  return privateIterator(iterator,next);
}
export function iterateEntries(value){
  const iterable=iterate(value),iterator=apply(iterable[Symbol.iterator],iterable,[]),next=iterator.next;
  const output=create(null);output.next=()=>{const step=apply(next,iterator,[]);if(!step.done&&isArray(step.value)){const array=step.value;step.value=new NativeProxy(array,{get(target,key){if(key===Symbol.iterator)return()=>privateIterator(apply(arrayIterator,target,[]),arrayNext);return get(target,key,target);}});}return step;};
  output[Symbol.iterator]=function(){return this};return output;
}
export function copyProfile(input) {
  const seen=new WeakSetIntrinsic();let count=0;
  function copy(value,depth) {
    if(++count>100000||depth>64)throw new TypeError('STATIC profile size/depth budget exceeded');
    if(value===null||typeof value==='string'||typeof value==='boolean')return value;
    if(typeof value==='number'){if(!NumberIntrinsic.isFinite(value))throw new TypeError('STATIC non-finite profile value');return value;}
    if(value===undefined)return undefined;
    if(typeof value!=='object')throw new TypeError('STATIC profiles must contain JSON data');
    if(seen.has(value))throw new TypeError('STATIC cyclic profile');seen.add(value);
    const fields=descriptors(value),output=isArray(value)?[]:create(null),keys=ownKeys(fields);
    for(let index=0;index<keys.length;index++){
      const key=keys[index],field=fields[key];if(typeof key!=='string'||key==='length'&&isArray(value))continue;
      if(!('value' in field))throw new TypeError('STATIC profile accessors are not allowed');
      const result=copy(field.value,depth+1);if(result!==undefined)put(output,key,result);
    }
    if(isArray(value)){output.length=fields.length.value;protectArray(output);}
    seen.delete(value);return output;
  }
  return copy(input,0);
}
