import { promiseThen, invoke, ObjectIntrinsic as Object, ReflectIntrinsic as Reflect, ProxyIntrinsic as Proxy, PromiseIntrinsic as Promise } from '../core/primordials.js';
import { definePatch } from '../core/patches.js';
import { getFingerprint } from '../core/config.js';
import { markModule } from '../core/guard.js';
import { replaceGetter, replaceMethod } from '../core/descriptors.js';
import { markNativeLike } from '../core/toString.js';
export function installNotifications() {
    const Notification = globalThis.Notification;
    if (typeof Notification !== 'function') {
        markModule('notifications', { status: 'unavailable' });
        return;
    }
    const fp = getFingerprint();
    if (fp.permission_states?.notifications === 'native') {
        markModule('notifications', { status: 'native', detail: 'explicit profile opt-out' });
        return;
    }
    const changed = replaceGetter(Notification, 'permission', () => 'denied');
    const wrapped = markNativeLike(new Proxy(Notification, {
        construct(native, args, newTarget) {
            if (!args.length)
                return Reflect.construct(native, args, newTarget);
            // DOMString conversion precedes denial; do not deliver a native notice.
            const title = `${args[0]}`;
            void title;
            throw new DOMException('Notification permission denied', 'NotAllowedError');
        },
    }), Notification);
    const request = replaceMethod(Notification, 'requestPermission', (_native, _receiver, args) => {
        // Static WebIDL operations are borrowable; detached calls must not escape
        // the denial policy through an otherwise valid native static operation.
        const callback = args[0];
        if (callback !== undefined && callback !== null && typeof callback !== 'function') {
            return Promise.reject(new TypeError('Notification permission callback must be a function'));
        }
        return promiseThen(Promise.resolve(), () => {
            if (callback)
                callback('denied');
            return 'denied';
        });
    });
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'Notification');
    if (descriptor?.configurable || descriptor?.writable) {
        definePatch(globalThis, 'Notification', { ...descriptor, value: wrapped });
        const constructor = Object.getOwnPropertyDescriptor(Notification.prototype, 'constructor');
        if (constructor?.configurable || constructor?.writable) {
            definePatch(Notification.prototype, 'constructor', { ...constructor, value: wrapped });
        }
    }
    const registration = globalThis.ServiceWorkerRegistration?.prototype;
    const getNotifications = registration?.getNotifications;
    if (typeof getNotifications === 'function') {
        replaceMethod(registration, 'showNotification', (_native, receiver) => promiseThen(Reflect.apply(getNotifications, receiver, []), () => {
            throw new DOMException('Notification permission denied', 'NotAllowedError');
        }));
        replaceMethod(registration, 'getNotifications', (native, receiver, args) => promiseThen(Reflect.apply(native, receiver, args), () => []));
    }
    // This realm refuses delivery without changing the user's browser settings.
    // Denial skips some native option conversions; other realms require bootstrap.
    markModule('notifications', { status: changed || request ? 'partial' : 'native',
        detail: 'denied permission/request/construction/delivery; native prototype, browser grant unchanged' });
}
