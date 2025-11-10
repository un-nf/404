/* Sandbox freeze script

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

(function sandboxLockdown() {
  'use strict';

  console.log('[404-SANDBOX] Initiating lockdown...');

  if (!window.__404_spoof_ready) {
    console.warn('[404-SANDBOX] WARNING: Spoofing not complete yet');

    window.__404_sandbox_retries = (window.__404_sandbox_retries || 0) + 1;

    console.warn(`[404-SANDBOX] Retry ${window.__404_sandbox_retries}/10 in 50ms...`);

    if (window.__404_sandbox_retries > 10) {
      console.error('[404-SANDBOX] CRITICAL: Spoofing failed to complete after 10 retries');
      console.error('[404-SANDBOX] Aborting lockdown to avoid locking partial state');
      console.error('[404-SANDBOX] System is vulnerable to tampering!');
      return;
    }

    setTimeout(sandboxLockdown, 50);

    return;
  }

  console.log('[404-SANDBOX] Spoofing layer confirmed ready');
  console.log(`[404-SANDBOX] Took ${window.__404_sandbox_retries || 0} retries`);

  const freeze = window.__404_freeze || Object.freeze;
  const isFrozen = window.__404_isFrozen || Object.isFrozen;

  console.log('[404-SANDBOX] Freezing Navigator.prototype...');
  try {
    freeze(Navigator.prototype);

    if (isFrozen(Navigator.prototype)) {
      console.log('[404-SANDBOX] Navigator.prototype frozen');
    } else {
      console.error('[404-SANDBOX] Failed to freeze Navigator.prototype');
    }
  } catch (e) {
    console.error('[404-SANDBOX] Error freezing Navigator.prototype:', e);
  }

  console.log('[404-SANDBOX] Freezing Screen.prototype...');
  try {
    freeze(Screen.prototype);

    if (isFrozen(Screen.prototype)) {
      console.log('[404-SANDBOX] Screen.prototype frozen');
    } else {
      console.error('[404-SANDBOX] Failed to freeze Screen.prototype');
    }
  } catch (e) {
    console.error('[404-SANDBOX] Error freezing Screen.prototype:', e);
  }

  console.log('[404-SANDBOX] Freezing Object methods...');
  try {

    freeze(Object.defineProperty);

    freeze(Object.getOwnPropertyDescriptor);
    freeze(Object.getOwnPropertyDescriptors);

    freeze(Object.freeze);

    freeze(Object.seal);
    freeze(Object.preventExtensions);

    freeze(Object.isFrozen);
    freeze(Object.isSealed);
    freeze(Object.isExtensible);

    console.log('[404-SANDBOX] Object methods frozen');
  } catch (e) {
    console.error('[404-SANDBOX] Error freezing Object methods:', e);
  }

  console.log('[404-SANDBOX] Freezing Function methods...');
  try {

    freeze(Function.prototype.toString);

    freeze(Function.prototype.call);
    freeze(Function.prototype.apply);
    freeze(Function.prototype.bind);

    console.log('[404-SANDBOX] Function methods frozen');
  } catch (e) {
    console.error('[404-SANDBOX] Error freezing Function methods:', e);
  }

  console.log('[404-SANDBOX] Cleaning up globals...');

  const toRemove = [
    '__404_createNativeGetter',
    '__404_defineProperty',
    '__404_freeze',
    '__404_isFrozen',
    '__fpConfig',
    '__404_preflight_ready',
    '__404_config_ready',
    '__404_spoof_ready',
    '__404_preflight_version',
    '__404_config_version',
    '__404_sandbox_retries'
  ];

  let removed = 0;
  toRemove.forEach(function(name) {
    try {
      if (window[name] !== undefined) {
        delete window[name];
        removed++;
      }
    } catch (e) {
      console.warn('[404-SANDBOX] Could not remove global:', name, e);
    }
  });

  console.log(`[404-SANDBOX] Removed ${removed} global helpers`);

  console.log('[404-SANDBOX] Running final verification...');

  let verificationPassed = true;

  try {
    Object.defineProperty(Navigator.prototype, 'testProperty', {
      value: 'test'
    });
    console.error('[404-SANDBOX] FAIL: Was able to define new property on Navigator');
    verificationPassed = false;
  } catch (e) {
    console.log('[404-SANDBOX] PASS: Cannot define new properties on Navigator');
  }

  try {
    Object.defineProperty(Navigator.prototype, 'userAgent', {
      get: function() { return 'hacked'; }
    });
    console.error('[404-SANDBOX] FAIL: Was able to redefine userAgent');
    verificationPassed = false;
  } catch (e) {
    console.log('[404-SANDBOX] PASS: Cannot redefine userAgent');
  }

  if (!isFrozen(Navigator.prototype)) {
    console.error('[404-SANDBOX] FAIL: Navigator.prototype not frozen');
    verificationPassed = false;
  } else {
    console.log('[404-SANDBOX] PASS: Navigator.prototype is frozen');
  }

  if (!isFrozen(Screen.prototype)) {
    console.error('[404-SANDBOX] FAIL: Screen.prototype not frozen');
    verificationPassed = false;
  } else {
    console.log('[404-SANDBOX] PASS: Screen.prototype is frozen');
  }

  if (window.__fpConfig !== undefined) {
    console.warn('[404-SANDBOX] WARNING: __fpConfig still accessible');

  } else {
    console.log('[404-SANDBOX] PASS: Globals cleaned up');
  }

  if (verificationPassed) {
    window.__404_sandbox_active = true;
    window.__404_sandbox_version = '1.0.0';

    console.log('[404-SANDBOX]================================');
    console.log('[404-SANDBOX] COMPLETE');
    console.log('[404-SANDBOX] System hardened and immutable');
    console.log('[404-SANDBOX] Spoofing is now IRREVERSIBLE');
    console.log('[404-SANDBOX]================================');
  } else {
    console.error('[404-SANDBOX] FAILED');
    console.error('[404-SANDBOX] Some verifications did not pass');
    console.error('[404-SANDBOX] System may be vulnerable to tampering');
  }

  delete window.__404_sandbox_retries;

})();