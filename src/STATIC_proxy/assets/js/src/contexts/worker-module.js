import { startWorker } from './worker.js'

const encoded = new URL(import.meta.url).searchParams.get('profile')
if (encoded) {
  try {
    const bytes = Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')), (x) => x.charCodeAt(0))
    startWorker(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)))
  } catch {
    console.error('[STATIC] worker profile is invalid')
  }
}
