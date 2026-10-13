import { onRollback } from './patches.js'

const add=globalThis.EventTarget?.prototype.addEventListener
const remove=globalThis.EventTarget?.prototype.removeEventListener
const stop=globalThis.Event?.prototype.stopImmediatePropagation
const observed=new WeakMap()

// Constant profile observations do not transition when native state changes.
// Keep application-dispatched events and native registration/removal semantics.
export function suppressNativeTransitions(target,types) {
  if(!add||!remove||!stop)return false
  let installed=observed.get(target)
  if(!installed){installed=new Set();observed.set(target,installed)}
  for(const type of types) {
    if(installed.has(type))continue
    const listener=event=>{if(event.isTrusted)Reflect.apply(stop,event,[])}
    Reflect.apply(add,target,[type,listener,true]);installed.add(type)
    onRollback(()=>{Reflect.apply(remove,target,[type,listener,true]);installed.delete(type)})
  }
  return true
}
