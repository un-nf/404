import { stringReplace, stringCharCodeAt, JSONIntrinsic as JSON, Uint8ArrayIntrinsic as Uint8Array } from '../core/primordials.js';
import { startWorker } from './worker.js';
const encoded = new URL(import.meta.url).searchParams.get('profile');
if (encoded) {
    try {
        const bytes = Uint8Array.from(atob(stringReplace(stringReplace(encoded, /-/g, '+'), /_/g, '/')), (x) => stringCharCodeAt(x, 0));
        startWorker(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    }
    catch {
        console.error('[STATIC] worker profile is invalid');
    }
}
