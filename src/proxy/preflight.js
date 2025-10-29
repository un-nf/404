/* Preflight JavaScript

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

(function() {
  'use strict';

  const _ORIGINALS = {
    defineProperty: Object.defineProperty,
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
    freeze: Object.freeze,
    seal: Object.seal,
    isFrozen: Object.isFrozen,
    functionToString: Function.prototype.toString,
    functionBind: Function.prototype.bind,
    performanceNow: performance.now.bind(performance),
    mathRandom: Math.random.bind(Math),
    errorPrepareStackTrace: Error.prepareStackTrace,
  };

  const _spoofedFunctions = new WeakSet();

  Function.prototype.toString = function() {

    if (_spoofedFunctions.has(this)) {

      const name = this.name || '';

      if (name.startsWith('get ') || name.startsWith('set ')) {
        return `function ${name}() { [native code] }`;
      } else if (name) {
        return `function ${name}() { [native code] }`;
      } else {
        return 'function () { [native code] }';
      }
    }

    return _ORIGINALS.functionToString.call(this);
  };

  _spoofedFunctions.add(Function.prototype.toString);

  window.__404_createNativeGetter = function(value, propName) {

    const getter = function() {
      return value; 
    };

    _spoofedFunctions.add(getter);

    try {
      _ORIGINALS.defineProperty(getter, 'name', {
        value: 'get ' + propName,
        writable: false,
        enumerable: false,
        configurable: true
      });
    } catch (e) {

    }

    _ORIGINALS.freeze(getter);

    return getter;
  };

  _spoofedFunctions.add(window.__404_createNativeGetter);

  window.__404_defineProperty = function(obj, prop, value) {
    const getter = window.__404_createNativeGetter(value, prop);

    try {
      _ORIGINALS.defineProperty(obj, prop, {
        get: getter,
        enumerable: true,
        configurable: true, 
      });
    } catch (e) {
      console.error('[404-PREFLIGHT] Failed to define property:', prop, e);
    }
  };

  _spoofedFunctions.add(window.__404_defineProperty);

  performance.now = function() {
    const real = _ORIGINALS.performanceNow();

    const jitter = (_ORIGINALS.mathRandom() - 0.5) * 0.2;
    return real + jitter;
  };

  _spoofedFunctions.add(performance.now);

  Error.prepareStackTrace = function(error, structuredStackTrace) {
    if (!structuredStackTrace) {
      return error.toString();
    }

    const filtered = structuredStackTrace.filter(frame => {
      const fileName = frame.getFileName() || '';
      const functionName = frame.getFunctionName() || '';

      return !fileName.includes('404') &&
             !fileName.includes('preflight') &&
             !fileName.includes('fingerprint') &&
             !fileName.includes('sandbox') &&
             !functionName.includes('__404');
    });

    return error.toString() + '\n' + 
           filtered.map(f => '    at ' + f.toString()).join('\n');
  };

  window.__404_freeze = function(obj) {
    try {
      return _ORIGINALS.freeze(obj);
    } catch (e) {
      console.warn('[404-PREFLIGHT] Failed to freeze object:', e);
      return obj;
    }
  };

  _spoofedFunctions.add(window.__404_freeze);

  window.__404_isFrozen = function(obj) {
    return _ORIGINALS.isFrozen(obj);
  };

  _spoofedFunctions.add(window.__404_isFrozen);

  window.__404_preflight_ready = true;
  window.__404_preflight_version = '1.0.0';

  console.log('[404-PREFLIGHT] Foundation established');
  console.log('[404-PREFLIGHT] Function.toString override: Active');
  console.log('[404-PREFLIGHT] Native getter factory: Ready');
  console.log('[404-PREFLIGHT] Timing attack mitigation: Active');
  console.log('[404-PREFLIGHT] Stack trace sanitization: Active');

})();