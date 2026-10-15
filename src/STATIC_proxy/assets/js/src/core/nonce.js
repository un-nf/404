import { getRuntime } from './guard.js';
export function captureNonce() {
    const runtime = getRuntime();
    const currentScript = document.currentScript;
    if (currentScript) {
        const nonce = currentScript.nonce || currentScript.getAttribute('nonce');
        if (nonce) {
            runtime.nonce = nonce;
            return nonce;
        }
    }
    runtime.nonce = null;
    return null;
}
