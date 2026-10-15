import { NumberIntrinsic as Number } from './primordials.js'

export function createResourceBudget(maxBytes = 268435456, maxOperations = 4) {
  let bytes = 0, operations = 0
  return {
    reserve(width, height) {
      const needed = width * height * 16 // conservative extra RGBA surfaces/readback accounting
      if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 0 || height < 0 || !Number.isSafeInteger(needed) || needed < 0 || needed > maxBytes - bytes || operations >= maxOperations)
        throw new DOMException('Canvas masking resource budget exhausted', 'QuotaExceededError')
      bytes += needed; operations++
      let live = true
      return () => { if (live) { live = false; bytes -= needed; operations-- } }
    },
    counters: () => ({ bytes, operations })
  }
}
