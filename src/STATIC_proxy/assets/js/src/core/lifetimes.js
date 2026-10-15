// No browser handles in this module. Carry only a private liveness check across
// synchronous wrapper calls and explicitly chained native promises.
let current=()=>{};
export const currentLifetime=()=>current;
export function withinLifetime(check,operation){const previous=current;current=check;try{check();return operation();}finally{current=previous;}}
