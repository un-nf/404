import { iterateEntries } from '../core/primordials.js';
import { arrayEvery, ObjectIntrinsic as Object, ArrayIntrinsic as Array, WeakSetIntrinsic as WeakSet } from '../core/primordials.js';
import { markModule } from '../core/guard.js';
import { getFingerprint } from '../core/config.js';
import { replaceGetter } from '../core/descriptors.js';
export function installPlugins() {
    const fp = getFingerprint();
    const plugins = navigator.plugins, mimes = navigator.mimeTypes;
    const names = ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'];
    const expected = ['application/pdf', 'text/pdf'];
    const uniform = plugins && mimes && plugins.length === names.length && mimes.length === expected.length && arrayEvery(names, (name, index) => plugins[index]?.name === name) && arrayEvery(expected, (type, index) => mimes[index]?.type === type);
    const restricted = fp.pdf_inventory_policy === 'deny';
    const empty = fp.pdf_viewer_enabled === false && plugins?.length === 0 && mimes?.length === 0;
    const exposed = !restricted && (fp.pdf_viewer_enabled === true && uniform || empty);
    const deny = () => { throw new DOMException('PDF inventory unavailable under the selected profile', 'SecurityError'); };
    // Genuine indexed collections cannot be rebuilt or emptied by descriptors.
    // Permit only the standardized cohort; otherwise deny acquisition instead of
    // leaking a host inventory or manufacturing browser-internal object brands.
    replaceGetter(Object.getPrototypeOf(navigator), 'plugins', value => exposed ? value : deny());
    replaceGetter(Object.getPrototypeOf(navigator), 'mimeTypes', value => exposed ? value : deny());
    replaceGetter(Object.getPrototypeOf(navigator), 'pdfViewerEnabled', () => restricted ? fp.pdf_viewer_enabled === true : fp.pdf_viewer_enabled === false ? false : exposed ? true : deny());
    if (exposed && !empty) {
        const pluginSet = new WeakSet(Array.from(plugins)), mimeSet = new WeakSet(Array.from(mimes));
        for (const [key, value] of iterateEntries([['filename', 'internal-pdf-viewer'], ['description', 'Portable Document Format']]))
            replaceGetter(globalThis.Plugin?.prototype, key, (native, receiver) => pluginSet.has(receiver) ? value : native);
        for (const [key, value] of iterateEntries([['suffixes', 'pdf'], ['description', 'Portable Document Format']]))
            replaceGetter(globalThis.MimeType?.prototype, key, (native, receiver) => mimeSet.has(receiver) ? value : native);
    }
    markModule('plugins', { status: plugins ? 'partial' : 'unavailable',
        detail: exposed ? 'standardized genuine PDF/MIME cohort and normalized metadata; no viewer implementation or control of actual PDF handling' : 'profile PDF inventory acquisition denied; genuine empty/materialized collections and actual viewer control unavailable to proxy JavaScript' });
}
