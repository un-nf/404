// Realm-private patch journal. Never replace Object.defineProperty globally.
const define = Object.defineProperty
const descriptor = Object.getOwnPropertyDescriptor
let active = null

export function definePatch(target, key, value) {
  const before = descriptor(target, key)
  if (active && ((!before && value.configurable !== true) ||
      (before?.configurable && value.configurable === false) ||
      (before && !before.configurable && before.writable && value.writable === false))) {
    const error = new TypeError(`Non-reversible installation: ${String(key)}`)
    active.errors.push(error); throw error
  }
  try {
    const result = define(target, key, value)
    if (active) active.undo.push(() => before ? define(target, key, before) : Reflect.deleteProperty(target, key))
    return result
  } catch (error) {
    if (active) active.errors.push(error)
    throw error
  }
}

export function skippedPatch(key) {
  if (active) active.skipped.push(String(key))
}

export function deletePatch(target, key) {
  const before = descriptor(target, key)
  const deleted = Reflect.deleteProperty(target, key)
  if (!deleted) skippedPatch(key)
  if (deleted && before && active) active.undo.push(() => define(target, key, before))
  return deleted
}

export function onRollback(cleanup) {
  if (active) active.undo.push(cleanup)
}

export function transaction(operation) {
  const parent = active
  const journal = { undo: [], errors: [], skipped: [] }
  active = journal
  try {
    const result = operation()
    if (result && typeof result.then === 'function') throw new TypeError('Installers must be synchronous')
    // A legacy installer swallowing a define failure cannot claim success.
    if (journal.errors.length) throw journal.errors[0]
    return { changed: journal.undo.length, skipped: journal.skipped.slice() }
  } catch (error) {
    const rollbackErrors = []
    for (const undo of journal.undo.reverse()) {
      try { undo() } catch (failure) { rollbackErrors.push(String(failure.message || failure)) }
    }
    const failure = new Error(String(error?.message || error))
    failure.name = error?.name || 'Error'
    failure.rollbackErrors = rollbackErrors
    throw failure
  } finally { active = parent }
}
