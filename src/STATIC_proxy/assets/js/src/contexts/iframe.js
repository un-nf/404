import { iterate } from '../core/primordials.js';
import { invoke, arraySome, arrayForEach, ReflectIntrinsic as Reflect, ArrayIntrinsic as Array, WeakMapIntrinsic as WeakMap, WeakSetIntrinsic as WeakSet } from '../core/primordials.js';
import { getConfig } from '../core/config.js';
import { getRuntime, markModule } from '../core/guard.js';
import { findDescriptor, replaceGetter } from '../core/descriptors.js';
import { onRollback, onDispose } from '../core/patches.js';
export function installIframePropagation(initializeChild) {
    const runtime = getRuntime();
    const watched = new WeakSet();
    const busy = new WeakSet();
    const prototype = globalThis.HTMLIFrameElement?.prototype;
    const windowGetter = findDescriptor(prototype, 'contentWindow')?.descriptor.get;
    const documentGetter = findDescriptor(prototype, 'contentDocument')?.descriptor.get;
    runtime.frames = new WeakMap();
    function propagate(frame) {
        if (busy.has(frame))
            return;
        busy.add(frame);
        let outcome = 'unavailable';
        try {
            const child = windowGetter ? Reflect.apply(windowGetter, frame, []) : frame.contentWindow;
            const doc = documentGetter ? Reflect.apply(documentGetter, frame, []) : frame.contentDocument;
            if (child && child !== window && doc) {
                // A path, tag or nonce is not an execution acknowledgement.
                // The supplied coordinator owns document/generation deduplication.
                outcome = typeof initializeChild === 'function' ? initializeChild(child, doc, getConfig().raw) : 'unsupported';
            }
        }
        catch {
            outcome = 'unavailable';
        }
        runtime.frames.set(frame, outcome);
        busy.delete(frame);
    }
    function watch(frame) {
        if (!watched.has(frame)) {
            watched.add(frame);
            const loaded = () => propagate(frame);
            frame.addEventListener('load', loaded);
            onRollback(() => frame.removeEventListener('load', loaded));
        }
        propagate(frame);
    }
    for (const name of iterate(['contentWindow', 'contentDocument'])) {
        replaceGetter(prototype, name, (value, frame) => {
            propagate(frame);
            return value;
        });
    }
    arrayForEach(document.querySelectorAll('iframe'), watch);
    const observer = new MutationObserver((mutations) => {
        for (const mutation of iterate(mutations)) {
            for (const node of iterate(mutation.addedNodes)) {
                if (node.nodeType !== 1)
                    continue;
                if (node.localName === 'iframe')
                    watch(node);
                arrayForEach(node.querySelectorAll?.('iframe'), watch);
            }
        }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    onRollback(() => observer.disconnect());
    onDispose(() => observer.disconnect());
    markModule('iframePropagation', { status: 'partial', detail: 'synchronous accessible-frame getters and observer/load fallback; early child code and CSP gaps remain' });
}
