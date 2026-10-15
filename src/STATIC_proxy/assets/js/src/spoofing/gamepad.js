import { stringPadStart, numberString } from '../core/primordials.js';
import { getRuntime, markModule } from '../core/guard.js';
import { replaceGetter } from '../core/descriptors.js';
export function installGamepadSpoof() {
    const runtime = getRuntime();
    const proto = globalThis.Gamepad?.prototype;
    if (!proto || typeof navigator.getGamepads !== 'function') {
        markModule('gamepad', { status: 'unavailable' });
        return;
    }
    const changed = replaceGetter(proto, 'id', (id) => `Gamepad-${stringPadStart(numberString(runtime.entropy.hash(`${runtime.entropy.origin}:${runtime.entropy.sessionId}:${id}`), 16), 8, '0')}`);
    markModule('gamepad', { status: changed ? 'installed' : 'native',
        detail: 'native polling, null slots, events and haptics; ID observation only when patchable' });
}
