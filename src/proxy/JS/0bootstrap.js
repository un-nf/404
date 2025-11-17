/* JavaScript file for fingerprint spoofing proxy module

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

(function bootstrapExecutionControl() {
  'use strict';

  if (window.__404_bootstrap_active) {
    console.warn('[404] Bootstrap already loaded');
    return;
  }

  let trustedTypesPolicy = null;
  if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
      trustedTypesPolicy = window.trustedTypes.createPolicy('404-spoof-policy', {
        createScript: function(input) {

          return input;
        },
        createHTML: function(input) {
          return input;
        },
        createScriptURL: function(input) {
          return input;
        }
      });
      console.log('[404] Trusted Types policy active');
    } catch (e) {
      console.warn('[404] CSP Trusted Types unavailable:', e.message);

    }
  }

  let CSP_NONCE = null;
  try {

    if (document.currentScript && document.currentScript.nonce) {
      CSP_NONCE = document.currentScript.nonce;
      console.log('[404] CSP nonce:', CSP_NONCE.substring(0, 8) + '...');
    } else if (document.currentScript && document.currentScript.getAttribute) {

      const nonceAttr = document.currentScript.getAttribute('nonce');
      if (nonceAttr) {
        CSP_NONCE = nonceAttr;
        console.log('[404-BOOTSTRAP] Detected CSP nonce (via getAttribute):', CSP_NONCE.substring(0, 12) + '...');
      }
    }

    if (!CSP_NONCE) {
      const scripts = document.querySelectorAll('script[nonce]');
      if (scripts.length > 0) {
        CSP_NONCE = scripts[0].nonce || scripts[0].getAttribute('nonce');
        console.log('[404-BOOTSTRAP] Detected CSP nonce from other script:', CSP_NONCE.substring(0, 12) + '...');
      }
    }

  } catch (e) {
    console.warn('[404] Nonce detection error:', e.message);
  }

  const NATIVE = {

    eval: window.eval,
    Function: window.Function,

    createElement: Document.prototype.createElement,
    createElementNS: Document.prototype.createElementNS,
    appendChild: Node.prototype.appendChild,
    insertBefore: Node.prototype.insertBefore,
    replaceChild: Node.prototype.replaceChild,
    setAttribute: Element.prototype.setAttribute,
    setAttributeNS: Element.prototype.setAttributeNS,

    defineProperty: Object.defineProperty,
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,

    HTMLIFrameElement: window.HTMLIFrameElement,

    Error: window.Error,

    bind: Function.prototype.bind,
    call: Function.prototype.call,
    apply: Function.prototype.apply
  };

  function getSpoofedGlobals() {
    return window.__404_spoofed_globals || {};
  }

  function generateSpoofedBindings() {
    const spoofed = getSpoofedGlobals();
    const bindings = [];

    const objectsToSpoof = [
      'navigator',
      'screen', 
      'Date',
      'Intl',
      'performance',
      'OfflineAudioContext',
      'AudioContext',
      'webkitAudioContext',
      'webkitOfflineAudioContext'
    ];

    objectsToSpoof.forEach(function(objName) {

      if (spoofed[objName] !== undefined) {
        bindings.push(
          `const ${objName} = (function() {` +
          `  try { return window.__404_spoofed_globals.${objName} || window.${objName}; }` +
          `  catch(e) { return window.${objName}; }` +
          `})();`
        );
      }
    });

    return bindings.join('\n');
  }

  const originalEval = NATIVE.eval;

  window.eval = function evaluateWithSpoofedBindings(code) {

    if (typeof code !== 'string') {
      return originalEval.call(this, code);
    }

    const bindings = generateSpoofedBindings();

    const wrappedCode = 
      '(function __404_eval_wrapper() {\n' +
      bindings + '\n' +
      '  return (function() {\n' +
      code + '\n' +
      '  }).call(this);\n' +
      '}).call(this)';

    try {
      return originalEval.call(this, wrappedCode);
    } catch (error) {

      console.warn('[404-BOOTSTRAP] eval wrapper failed, trying original:', error);
      return originalEval.call(this, code);
    }
  };

  window.eval.toString = function() {
    return 'function eval() { [native code] }';
  };

  console.log('[404] eval() wrapped');

  const OriginalFunction = NATIVE.Function;

  window.Function = function FunctionConstructorWithSpoofedBindings() {
    const args = Array.prototype.slice.call(arguments);

    const body = args.length > 0 ? String(args[args.length - 1]) : '';
    const params = args.slice(0, -1);

    const bindings = generateSpoofedBindings();

    const wrappedBody = bindings + '\n' + body;

    try {

      const constructorArgs = params.concat([wrappedBody]);
      return OriginalFunction.apply(this, constructorArgs);
    } catch (error) {

      console.warn('[404-BOOTSTRAP] Function constructor wrapper failed:', error);
      return OriginalFunction.apply(this, args);
    }
  };

  window.Function.prototype = OriginalFunction.prototype;
  Object.setPrototypeOf(window.Function, OriginalFunction);

  window.Function.toString = function() {
    return 'function Function() { [native code] }';
  };

  console.log('[404] Function() wrapped');

  Document.prototype.createElement = function(tagName, options) {
    const element = NATIVE.createElement.call(this, tagName, options);

    if (tagName && tagName.toLowerCase() === 'script') {
      element.__404_dynamic_script = true;

      const originalSetAttribute = element.setAttribute;
      element.setAttribute = function(name, value) {
        if (name === 'src') {
          console.log('[404-BOOTSTRAP] Dynamic script loading:', value);

        }
        return originalSetAttribute.call(this, name, value);
      };
    }

    return element;
  };

  console.log('[404] createElement() intercepted');

  Node.prototype.appendChild = function(child) {

    if (child && child.nodeType === 1 && child.tagName === 'SCRIPT' && child.__404_dynamic_script) {

      if (!child.__404_bootstrap_injected) {
        child.__404_bootstrap_injected = true;

        const bootstrapScript = document.createElement('script');

        if (CSP_NONCE) {
          bootstrapScript.setAttribute('nonce', CSP_NONCE);
        }

        const scriptContent = `

          (function() {
            if (!window.__404_bootstrap_active) {
              console.warn('[404-BOOTSTRAP] Dynamic script detected but bootstrap not active!');
              return;
            }

            console.log('[404-BOOTSTRAP] Dynamic script context prepared');
          })();
        `;

        bootstrapScript.textContent = trustedTypesPolicy 
          ? trustedTypesPolicy.createScript(scriptContent)
          : scriptContent;

        try {
          NATIVE.appendChild.call(this, bootstrapScript);
          console.log('[404-BOOTSTRAP]  Injected bootstrap before dynamic script');
        } catch (e) {
          console.warn('[404-BOOTSTRAP] Failed to inject bootstrap:', e);
        }
      }
    }

    return NATIVE.appendChild.call(this, child);
  };

  console.log('[404] appendChild() monitored');

  Node.prototype.insertBefore = function(newNode, referenceNode) {

    if (newNode && newNode.nodeType === 1 && newNode.tagName === 'SCRIPT' && newNode.__404_dynamic_script) {

      if (!newNode.__404_bootstrap_injected) {
        newNode.__404_bootstrap_injected = true;

        const bootstrapScript = document.createElement('script');

        if (CSP_NONCE) {
          bootstrapScript.setAttribute('nonce', CSP_NONCE);
        }

        const scriptContent = `
          (function() {
            if (window.__404_bootstrap_active) {
              console.log('[404-BOOTSTRAP] Dynamic insertBefore context prepared');
            }
          })();
        `;

        bootstrapScript.textContent = trustedTypesPolicy 
          ? trustedTypesPolicy.createScript(scriptContent)
          : scriptContent;

        try {
          NATIVE.insertBefore.call(this, bootstrapScript, referenceNode);
          console.log('[404-BOOTSTRAP]  Injected bootstrap before insertBefore script');
        } catch (e) {
          console.warn('[404-BOOTSTRAP] Failed to inject bootstrap:', e);
        }
      }
    }

    return NATIVE.insertBefore.call(this, newNode, referenceNode);
  };

  console.log('[404] insertBefore() monitored');

  Node.prototype.replaceChild = function(newChild, oldChild) {

    if (newChild && newChild.nodeType === 1 && newChild.tagName === 'SCRIPT' && newChild.__404_dynamic_script) {

      if (!newChild.__404_bootstrap_injected) {
        newChild.__404_bootstrap_injected = true;
        console.log('[404-BOOTSTRAP] Marked script for bootstrap injection');
      }
    }

    return NATIVE.replaceChild.call(this, newChild, oldChild);
  };

  console.log('[404] replaceChild() monitored');

  function propagateToIframe(iframe) {
    try {

      const iframeWindow = iframe.contentWindow;
      const iframeDocument = iframe.contentDocument;

      if (!iframeWindow || !iframeDocument) {
        console.warn('[404-BOOTSTRAP] Cannot access iframe (cross-origin?)');
        return;
      }

      console.log('[404-BOOTSTRAP] Propagating protections to iframe');

      if (iframeWindow.__404_bootstrap_active) {
        console.log('[404-BOOTSTRAP] Iframe already protected');
        return;
      }

      if (window.__404_spoofed_globals) {
        iframeWindow.__404_spoofed_globals = window.__404_spoofed_globals;
      }

      iframeWindow.eval = window.eval;
      iframeWindow.Function = window.Function;

      try {
        Object.defineProperty(iframeWindow, 'navigator', {
          value: window.navigator,
          writable: false,
          enumerable: true,
          configurable: false
        });
        console.log('[404-BOOTSTRAP]  Iframe navigator replaced');
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe navigator:', e.message);
        try {
          iframeWindow.navigator = window.navigator;
        } catch (e2) {
          console.error('[404-BOOTSTRAP] Failed to replace iframe navigator');
        }
      }

      try {
        Object.defineProperty(iframeWindow, 'screen', {
          value: window.screen,
          writable: false,
          enumerable: true,
          configurable: false
        });
        console.log('[404-BOOTSTRAP]  Iframe screen replaced');
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe screen:', e.message);
        try {
          iframeWindow.screen = window.screen;
        } catch (e2) {
          console.error('[404-BOOTSTRAP] Failed to replace iframe screen');
        }
      }

      try {
        Object.defineProperty(iframeWindow, 'performance', {
          value: window.performance,
          writable: false,
          enumerable: true,
          configurable: false
        });
        console.log('[404-BOOTSTRAP]  Iframe performance replaced');
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe performance:', e.message);
        try {
          iframeWindow.performance = window.performance;
        } catch (e2) {
          console.error('[404-BOOTSTRAP] Failed to replace iframe performance');
        }
      }

      try {
        Object.defineProperty(iframeWindow, 'devicePixelRatio', {
          get: function() {
            return window.devicePixelRatio;
          },
          configurable: true
        });
        Object.defineProperty(iframeWindow, 'innerWidth', {
          get: function() {
            return window.innerWidth;
          },
          configurable: true
        });
        Object.defineProperty(iframeWindow, 'innerHeight', {
          get: function() {
            return window.innerHeight;
          },
          configurable: true
        });
        Object.defineProperty(iframeWindow, 'outerWidth', {
          get: function() {
            return window.outerWidth;
          },
          configurable: true
        });
        Object.defineProperty(iframeWindow, 'outerHeight', {
          get: function() {
            return window.outerHeight;
          },
          configurable: true
        });
        console.log('[404-BOOTSTRAP]  Iframe viewport dimensions and devicePixelRatio replaced');
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe viewport:', e.message);
      }

      if (window.__fpConfig) {
        iframeWindow.__fpConfig = window.__fpConfig;
      }

      try {
        if (window.Date.prototype.getTimezoneOffset.toString().indexOf('[native code]') === -1) {
          iframeWindow.Date.prototype.getTimezoneOffset = window.Date.prototype.getTimezoneOffset;
          iframeWindow.Date.prototype.toString = window.Date.prototype.toString;
          iframeWindow.Date.prototype.toTimeString = window.Date.prototype.toTimeString;
          iframeWindow.Date.prototype.toLocaleString = window.Date.prototype.toLocaleString;
          console.log('[404-BOOTSTRAP]  Iframe Date.prototype timezone methods replaced');
        }
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe Date methods:', e.message);
      }

      try {
        if (window.Intl && window.Intl.DateTimeFormat && window.Intl.DateTimeFormat.toString().indexOf('[native code]') === -1) {
          iframeWindow.Intl.DateTimeFormat = window.Intl.DateTimeFormat;
          console.log('[404-BOOTSTRAP]  Iframe Intl.DateTimeFormat replaced');
        }
      } catch (e) {
        console.warn('[404-BOOTSTRAP] Could not replace iframe Intl.DateTimeFormat:', e.message);
      }

      iframeWindow.__404_bootstrap_active = true;
      iframeWindow.__404_shim_active = true;
      iframeWindow.__404_config_ready = true;

      console.log('[404-BOOTSTRAP]  Iframe fully protected with spoofed globals');
    } catch (error) {

      console.warn('[404-BOOTSTRAP] Could not propagate to iframe:', error.message);
    }
  }

  if (window.MutationObserver) {
    const iframeObserver = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.tagName === 'IFRAME') {
            console.log('[404-BOOTSTRAP] Iframe detected via MutationObserver');

            node.addEventListener('load', function() {
              propagateToIframe(node);
            });
          }
        });
      });
    });

    iframeObserver.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  try {
    Object.defineProperty(window, 'eval', {
      value: window.eval,
      writable: false,
      enumerable: false,
      configurable: false
    });

    Object.defineProperty(window, 'Function', {
      value: window.Function,
      writable: false,
      enumerable: false,
      configurable: false
    });
  } catch (error) {
    console.warn('[404] Could not lock globals:', error.message);
  }

  // Stack trace sanitization to hide spoofing artifacts
  try {
    const originalPrepareStackTrace = Error.prepareStackTrace;
    const stackDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, 'stack');
    
    if (stackDescriptor && stackDescriptor.get) {
      const originalStackGetter = stackDescriptor.get;
      Object.defineProperty(Error.prototype, 'stack', {
        get: function() {
          let stack = originalStackGetter.call(this);
          if (typeof stack === 'string') {
            // Remove lines containing spoofing artifacts
            stack = stack.replace(/.*404.*/gi, '')
                        .replace(/.*wrapper.*/gi, '')
                        .replace(/.*__fp.*/gi, '')
                        .replace(/.*spoofed.*/gi, '')
                        .replace(/\n\n+/g, '\n');
          }
          return stack;
        },
        configurable: true
      });
    }
  } catch (error) {
    // Stack trace sanitization failure is non-critical
  }  window.__404_bootstrap_active = true;
  window.__404_bootstrap_version = '2.0.0';

  console.log('[404] Bootstrap complete - execution context protected');

})();