/* STATIC Proxy Bootstrap v4 (AGPL-3.0) */
;(function staticBootstrap() {
  'use strict';

  const MARK = '__static_bootstrap_active';
  if (window[MARK]) {
    console.warn('[STATIC] bootstrap already applied');
    return;
  }

  const native = {
    eval: window.eval,
    Function: window.Function,
    createElement: Document.prototype.createElement,
    createElementNS: Document.prototype.createElementNS,
    appendChild: Node.prototype.appendChild,
    insertBefore: Node.prototype.insertBefore,
    replaceChild: Node.prototype.replaceChild,
    adoptNode: Document.prototype.adoptNode,
    importNode: Document.prototype.importNode,
    setAttribute: Element.prototype.setAttribute,
    setAttributeNS: Element.prototype.setAttributeNS,
    defineProperty: Object.defineProperty,
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
    HTMLIFrameElement: window.HTMLIFrameElement,
  };

  function captureNonce() {
    const sources = [
      () => document.currentScript && document.currentScript.nonce,
      () => document.currentScript && document.currentScript.getAttribute && document.currentScript.getAttribute('nonce'),
      () => {
        const tagged = document.querySelector('script[nonce]');
        return tagged ? tagged.nonce || tagged.getAttribute('nonce') : null;
      },
      () => window.__STATIC_CSP_NONCE,
    ];
    for (const probe of sources) {
      try {
        const value = probe();
        if (value) {
          return value;
        }
      } catch (_) {}
    }
    return null;
  }

  const STATE = {
    nonce: captureNonce(),
    trustedTypes: null,
  };
  const scriptGuardsEnabled = Boolean(STATE.nonce);

  function guardDisabled() {
    return window.__STATIC_DISABLE_CANVAS_GUARD === true;
  }

  function hashString(input) {
    const text = String(input || 'static');
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = Math.imul(31, hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return hash >>> 0;
  }

  function createRng(seedValue) {
    let state = (seedValue >>> 0) || 0x9E3779B1;
    return function rng() {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) / 0xFFFFFFFF;
    };
  }

  function deriveSessionSeed(scope) {
    const inlineSeed = (scope && scope.__STATIC_SESSION_ID)
      || window.__STATIC_SESSION_ID
      || window.__404_session_id
      || STATE.canvasSeed;
    if (inlineSeed) {
      return String(inlineSeed);
    }
    STATE.canvasSeed = `${Date.now().toString(36)}:${Math.random().toString(16).slice(2)}`;
    return STATE.canvasSeed;
  }

  function deriveOriginKey(scope) {
    try {
      const view = scope || window;
      const loc = view.location;
      if (loc && typeof loc.origin === 'string') {
        return loc.origin;
      }
      if (loc && loc.protocol && (loc.host || loc.hostname)) {
        const host = loc.host || loc.hostname;
        return `${loc.protocol}//${host}`;
      }
    } catch (_) {
      /* ignored */
    }
    return 'opaque-origin';
  }

  const CanvasNoiseGuard = (() => {
    const originState = new Map();
    const highValueMap = typeof WeakMap === 'function' ? new WeakMap() : new Map();
    let nativeGetImageData = null;
    const defaultStrategy = Object.freeze({
      mode: 'session',
      stride: 17,
      delta_min: 1,
      delta_max: 3,
      alpha: true,
      context_aware: true,
      ephemeral: {
        enabled: true,
        scale: 1.5,
      },
    });

    function cloneStrategy() {
      return {
        mode: defaultStrategy.mode,
        stride: defaultStrategy.stride,
        delta_min: defaultStrategy.delta_min,
        delta_max: defaultStrategy.delta_max,
        alpha: defaultStrategy.alpha,
        context_aware: defaultStrategy.context_aware,
        ephemeral: {
          enabled: defaultStrategy.ephemeral.enabled,
          scale: defaultStrategy.ephemeral.scale,
        },
      };
    }

    function mergeStrategy(target, source) {
      if (!source || typeof source !== 'object') {
        return;
      }
      if (typeof source.mode === 'string') {
        target.mode = source.mode;
      }
      if (Number.isFinite(source.stride)) {
        target.stride = Math.max(3, Number(source.stride));
      }
      if (Array.isArray(source.delta)) {
        const [deltaMin, deltaMax] = source.delta;
        if (Number.isFinite(deltaMin)) {
          target.delta_min = Number(deltaMin);
        }
        if (Number.isFinite(deltaMax)) {
          target.delta_max = Number(deltaMax);
        }
      }
      if (Number.isFinite(source.delta_min)) {
        target.delta_min = Number(source.delta_min);
      }
      if (Number.isFinite(source.delta_max)) {
        target.delta_max = Number(source.delta_max);
      }
      if (typeof source.alpha === 'boolean') {
        target.alpha = source.alpha;
      }
      if (typeof source.context_aware === 'boolean') {
        target.context_aware = source.context_aware;
      }
      if (source.ephemeral && typeof source.ephemeral === 'object') {
        if (typeof source.ephemeral.enabled === 'boolean') {
          target.ephemeral.enabled = source.ephemeral.enabled;
        }
        if (Number.isFinite(source.ephemeral.scale)) {
          target.ephemeral.scale = Number(source.ephemeral.scale);
        }
      }
      target.delta_max = Math.max(target.delta_min, target.delta_max);
    }

    function resolveStrategy(scope) {
      const result = cloneStrategy();
      mergeStrategy(result, window.__static_canvas_strategy);
      if (scope && scope !== window) {
        mergeStrategy(result, scope.__static_canvas_strategy);
      }
      return result;
    }

    function getOriginState(originKey) {
      let state = originState.get(originKey);
      if (!state) {
        state = {
          persistentCounter: 0,
          ephemeralCounter: 0,
          logged: false,
        };
        originState.set(originKey, state);
      }
      return state;
    }

    function shouldApplyEphemeral(canvas, reason) {
      if (!canvas || !reason) {
        return false;
      }
      const store = highValueMap;
      let entry = store.get(canvas);
      if (!entry) {
        entry = new Set();
        store.set(canvas, entry);
      }
      if (entry.has(reason)) {
        return false;
      }
      entry.add(reason);
      return true;
    }

    function resolveHandler(scope) {
      if (scope && typeof scope.__static_canvas_noise_handler === 'function') {
        return scope.__static_canvas_noise_handler;
      }
      if (typeof window.__static_canvas_noise_handler === 'function') {
        return window.__static_canvas_noise_handler;
      }
      return null;
    }

    function clampByte(value) {
      if (value < 0) {
        return 0;
      }
      if (value > 255) {
        return 255;
      }
      return value;
    }

    function applyTinyNoise(data) {
      for (let i = 3; i < data.length; i += 4) {
        data[i] = data[i] ^ 0x1F;
      }
    }

    function applyBandNoise(data, plan) {
      const { persistentRng, strategy, width, height } = plan;
      const rowStep = strategy.context_aware !== false
        ? Math.max(3, Math.floor(height / 12) || 7)
        : 1;
      const colStep = Math.max(3, Math.floor(strategy.stride) || 3);
      const deltaRange = strategy.delta_max - strategy.delta_min;
      for (let y = 0; y < height; y += rowStep) {
        const rowOffset = y * width * 4;
        for (let x = 0; x < width; x += colStep) {
          const idx = rowOffset + (x * 4);
          if (idx >= data.length) {
            break;
          }
          const deltaMagnitude = strategy.delta_min + (deltaRange * persistentRng());
          const signed = persistentRng() > 0.5 ? deltaMagnitude : -deltaMagnitude;
          const delta = Math.round(signed);
          data[idx] = clampByte(data[idx] + delta);
          if ((idx + 1) < data.length) {
            data[idx + 1] = clampByte(data[idx + 1] - delta);
          }
          if ((idx + 2) < data.length) {
            data[idx + 2] = clampByte(data[idx + 2] + Math.round(delta * 0.5));
          }
          if (strategy.alpha && (idx + 3) < data.length) {
            data[idx + 3] = clampByte(data[idx + 3] ^ (Math.abs(delta) & 0x0F));
          }
        }
      }
    }

    function applyEphemeralNoise(data, plan) {
      const rng = plan.ephemeralRng;
      if (!rng) {
        return;
      }
      const totalPixels = Math.max(1, plan.width * plan.height);
      const hits = Math.max(3, Math.floor(totalPixels / Math.max(64, plan.strategy.stride * 8)));
      const scale = plan.strategy.ephemeral.scale || 1;
      for (let i = 0; i < hits; i += 1) {
        const pixelIndex = Math.floor(rng() * totalPixels) * 4;
        if (pixelIndex >= data.length) {
          continue;
        }
        const jitter = (rng() - 0.5) * 2 * scale;
        data[pixelIndex] = clampByte(data[pixelIndex] + jitter);
        if ((pixelIndex + 1) < data.length) {
          data[pixelIndex + 1] = clampByte(data[pixelIndex + 1] + jitter);
        }
        if ((pixelIndex + 2) < data.length) {
          data[pixelIndex + 2] = clampByte(data[pixelIndex + 2] - jitter);
        }
      }
    }

    function executePlan(details, plan) {
      if (!details || !plan || !details.imageData || !details.imageData.data) {
        return;
      }
      const width = plan.width || details.imageData.width || 0;
      const height = plan.height || details.imageData.height || 0;
      plan.width = width;
      plan.height = height;
      if (!width || !height) {
        return;
      }
      const data = details.imageData.data;
      if (width <= 16 || height <= 16) {
        applyTinyNoise(data);
      } else {
        applyBandNoise(data, plan);
      }
      if (plan.applyEphemeral) {
        applyEphemeralNoise(data, plan);
      }
    }

    function buildNoisePlan(details) {
      const scope = details.scope || window;
      const originKey = deriveOriginKey(scope);
      const state = getOriginState(originKey);
      const strategy = resolveStrategy(scope);
      const sessionSeed = deriveSessionSeed(scope);
      const baseSeed = hashString(`${sessionSeed}::${originKey}`);
      let persistentSeed = baseSeed;
      if (strategy.mode === 'per_call') {
        state.persistentCounter += 1;
        persistentSeed = hashString(`${baseSeed}::${state.persistentCounter}::${details.reason || 'call'}`);
      }
      const plan = {
        scope,
        originKey,
        strategy,
        state,
        reason: details.reason || 'canvas',
        width: details.width || (details.imageData && details.imageData.width) || 0,
        height: details.height || (details.imageData && details.imageData.height) || 0,
        applyEphemeral: Boolean(details.applyEphemeral && strategy.ephemeral.enabled),
        persistentRng: createRng(persistentSeed),
        baseSeed,
      };
      if (plan.applyEphemeral) {
        state.ephemeralCounter += 1;
        const epSeed = hashString(`${baseSeed}::ephemeral::${state.ephemeralCounter}::${plan.reason}`);
        plan.ephemeralRng = createRng(epSeed);
      }
      if (!state.logged && window.__STATIC_CANVAS_GUARD_SILENT !== true) {
        state.logged = true;
        console.info('[STATIC] canvas guard active', originKey, strategy.mode);
      }
      return plan;
    }

    function applyNoise(details) {
      if (guardDisabled()) {
        return;
      }
      if (!details || !details.imageData || !details.imageData.data) {
        return;
      }
      if (!details.width) {
        details.width = details.imageData.width || 0;
      }
      if (!details.height) {
        details.height = details.imageData.height || 0;
      }
      const plan = buildNoisePlan(details);
      details.plan = plan;
      let handled = false;
      const handler = resolveHandler(details.scope);
      if (handler) {
        try {
          handled = handler(details) === true;
        } catch (err) {
          console.warn('[STATIC] canvas handler error:', err && err.message ? err.message : err);
        }
      }
      if (!handled) {
        executePlan(details, plan);
      }
      if (details.writeBack && !details.writeBackHandled && details.context && typeof details.context.putImageData === 'function') {
        try {
          details.context.putImageData(details.imageData, 0, 0);
        } catch (_) {
          /* ignored */
        }
      }
    }

    function getScopeFromCanvas(canvas) {
      if (!canvas || !canvas.ownerDocument || !canvas.ownerDocument.defaultView) {
        return window;
      }
      return canvas.ownerDocument.defaultView;
    }

    function resolveContext(canvas) {
      if (!canvas || typeof canvas.getContext !== 'function') {
        return null;
      }
      try {
        return canvas.getContext('2d');
      } catch (_) {
        return null;
      }
    }

    function mutateCanvasSnapshot(canvas, reason, options) {
      if (!canvas) {
        return null;
      }
      const ctx = resolveContext(canvas);
      if (!ctx || typeof ctx.putImageData !== 'function') {
        return null;
      }
      const width = canvas.width || (ctx.canvas && ctx.canvas.width) || 0;
      const height = canvas.height || (ctx.canvas && ctx.canvas.height) || 0;
      if (!width || !height) {
        return null;
      }
      const getter = nativeGetImageData || (ctx && ctx.getImageData);
      if (typeof getter !== 'function') {
        return null;
      }
      let imageData;
      try {
        imageData = getter.call(ctx, 0, 0, width, height);
      } catch (_) {
        return null;
      }
      if (!imageData || !imageData.data) {
        return null;
      }
      let backup = null;
      const restoreEnabled = !options || options.restore !== false;
      if (restoreEnabled) {
        try {
          backup = new Uint8ClampedArray(imageData.data);
        } catch (_) {
          backup = null;
        }
      }
      const scope = (options && options.scope) || getScopeFromCanvas(canvas);
      applyNoise({
        scope,
        canvas,
        context: ctx,
        imageData,
        writeBack: true,
        reason,
        width,
        height,
        applyEphemeral: shouldApplyEphemeral(canvas, reason),
      });
      if (!restoreEnabled || !backup) {
        return null;
      }
      return () => {
        try {
          imageData.data.set(backup);
          ctx.putImageData(imageData, 0, 0);
        } catch (_) {
          /* ignored */
        }
      };
    }

    return {
      install() {
        if (guardDisabled()) {
          return;
        }
        const Canvas = window.HTMLCanvasElement;
        const Context = window.CanvasRenderingContext2D;
        if (!Canvas || !Context || Canvas.prototype.__static_canvas_guarded) {
          return;
        }

        const canvasProto = Canvas.prototype;
        const ctxProto = Context.prototype;
        const originalGetImageData = typeof ctxProto.getImageData === 'function'
          ? ctxProto.getImageData
          : null;
        const originalToDataURL = typeof canvasProto.toDataURL === 'function'
          ? canvasProto.toDataURL
          : null;
        const originalToBlob = typeof canvasProto.toBlob === 'function'
          ? canvasProto.toBlob
          : null;
        const originalTransferToImageBitmap = typeof canvasProto.transferToImageBitmap === 'function'
          ? canvasProto.transferToImageBitmap
          : null;

        if (originalGetImageData) {
          nativeGetImageData = originalGetImageData;
          ctxProto.getImageData = function patchedGetImageData() {
            const data = originalGetImageData.apply(this, arguments);
            try {
              const canvas = this && this.canvas ? this.canvas : null;
              applyNoise({
                scope: getScopeFromCanvas(canvas),
                canvas,
                context: this,
                imageData: data,
                writeBack: false,
                reason: 'getImageData',
                width: data && data.width,
                height: data && data.height,
                applyEphemeral: false,
              });
            } catch (_) {
              /* ignored */
            }
            return data;
          };
        }

        if (originalToDataURL) {
          canvasProto.toDataURL = function patchedToDataURL() {
            const restore = mutateCanvasSnapshot(this, 'toDataURL');
            try {
              return originalToDataURL.apply(this, arguments);
            } finally {
              if (typeof restore === 'function') {
                restore();
              }
            }
          };
        }

        if (originalToBlob) {
          canvasProto.toBlob = function patchedToBlob(callback, type, quality) {
            const restore = mutateCanvasSnapshot(this, 'toBlob');
            let wrapped = callback;
            if (typeof callback === 'function') {
              wrapped = function wrappedBlob(blob) {
                if (typeof restore === 'function') {
                  restore();
                }
                return callback.call(this, blob);
              };
            } else if (typeof restore === 'function') {
              setTimeout(() => restore(), 0);
            }
            return originalToBlob.call(this, wrapped, type, quality);
          };
        }

        if (originalTransferToImageBitmap) {
          canvasProto.transferToImageBitmap = function patchedTransferToImageBitmap() {
            const restore = mutateCanvasSnapshot(this, 'transferToImageBitmap');
            try {
              return originalTransferToImageBitmap.apply(this, arguments);
            } finally {
              if (typeof restore === 'function') {
                restore();
              }
            }
          };
        }

        const Offscreen = window.OffscreenCanvas;
        if (Offscreen && Offscreen.prototype) {
          const offscreenProto = Offscreen.prototype;
          const offscreenConvert = typeof offscreenProto.convertToBlob === 'function'
            ? offscreenProto.convertToBlob
            : null;
          const offscreenTransfer = typeof offscreenProto.transferToImageBitmap === 'function'
            ? offscreenProto.transferToImageBitmap
            : null;
          if (offscreenConvert) {
            offscreenProto.convertToBlob = function patchedConvertToBlob() {
              const restore = mutateCanvasSnapshot(this, 'offscreen.convertToBlob');
              const result = offscreenConvert.apply(this, arguments);
              if (result && typeof result.then === 'function') {
                return result.finally(() => {
                  if (typeof restore === 'function') {
                    restore();
                  }
                });
              }
              if (typeof restore === 'function') {
                restore();
              }
              return result;
            };
          }
          if (offscreenTransfer) {
            offscreenProto.transferToImageBitmap = function patchedOffscreenTransfer() {
              const restore = mutateCanvasSnapshot(this, 'offscreen.transferToImageBitmap');
              try {
                return offscreenTransfer.apply(this, arguments);
              } finally {
                if (typeof restore === 'function') {
                  restore();
                }
              }
            };
          }
        }

        Object.defineProperty(canvasProto, '__static_canvas_guarded', {
          value: true,
          writable: false,
          configurable: false,
          enumerable: false,
        });
        Object.defineProperty(window, '__static_canvas_plan_executor', {
          value: executePlan,
          writable: true,
          configurable: true,
          enumerable: false,
        });
        window.__static_canvas_guarded = true;
      },
    };
  })();

  CanvasNoiseGuard.install();

  if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
      STATE.trustedTypes = window.trustedTypes.createPolicy('static-proxy', {
        createScript: (input) => input,
        createHTML: (input) => input,
        createScriptURL: (input) => input,
      });
    } catch (err) {
      console.warn('[STATIC] trusted types unavailable:', err.message);
    }
  }

  try {
    if (window.chrome && window.chrome.runtime) {
      delete window.chrome;
    }
  } catch (err) {
    console.warn('[STATIC] failed to drop window.chrome:', err.message);
  }

  function getSpoofedGlobals() {
    return window.__404_spoofed_globals || window.__static_spoofed_globals || {};
  }

  function emitBindings() {
    const bindings = [];
    const spoofed = getSpoofedGlobals();
    const targets = ['navigator', 'screen', 'performance', 'Date', 'Intl', 'OfflineAudioContext', 'AudioContext'];
    targets.forEach((key) => {
      if (spoofed[key] !== undefined || window[key] !== undefined) {
        bindings.push(
          `const ${key} = (function(){` +
            `try { return (window.__404_spoofed_globals && window.__404_spoofed_globals.${key}) || (window.__static_spoofed_globals && window.__static_spoofed_globals.${key}) || window.${key}; }` +
            `catch (_) { return window.${key}; }` +
          `})();`
        );
      }
    });
    return bindings.join('\n');
  }

  const SCRIPT_TAG = 'script';
  const IFRAME_TAG = 'iframe';

  function normalizeTagName(tag) {
    return typeof tag === 'string' ? tag.toLowerCase() : '';
  }

  function isScriptNode(node) {
    return Boolean(
      node &&
      ((node.tagName && normalizeTagName(node.tagName) === SCRIPT_TAG) || node.__static_dynamic_script)
    );
  }

  function isIframeNode(node) {
    return Boolean(node && node.tagName && normalizeTagName(node.tagName) === IFRAME_TAG);
  }

  function tagScript(element) {
    if (!element || element.__static_bound) {
      return element;
    }
    element.__static_bound = true;
    if (STATE.nonce && !element.nonce) {
      element.setAttribute('nonce', STATE.nonce);
    }
    return element;
  }

  function markDynamicScript(node) {
    if (!node || node.__static_dynamic_script) {
      return node;
    }
    node.__static_dynamic_script = true;
    tagScript(node);
    return node;
  }

  function trackSpecialNode(node, tagLower) {
    if (!node || !tagLower) {
      return node;
    }
    if (tagLower === SCRIPT_TAG || tagLower.endsWith(':script')) {
      markDynamicScript(node);
    } else if (tagLower === IFRAME_TAG) {
      queueIframeHook(node);
    }
    return node;
  }

  function traverseForSpecialDescendants(root) {
    if (!root || !root.childNodes) {
      return false;
    }
    let foundScript = false;
    const stack = Array.from(root.childNodes);
    while (stack.length) {
      const current = stack.shift();
      if (!current) {
        continue;
      }
      if (isScriptNode(current)) {
        markDynamicScript(current);
        foundScript = true;
      } else if (isIframeNode(current)) {
        queueIframeHook(current);
      }
      if (current.childNodes && current.childNodes.length) {
        stack.push(...current.childNodes);
      }
    }
    return foundScript;
  }

  function markSubtree(node) {
    if (!node) {
      return false;
    }
    if (isScriptNode(node)) {
      markDynamicScript(node);
      return true;
    }
    if (isIframeNode(node)) {
      queueIframeHook(node);
    }
    if (!node.childNodes || !node.childNodes.length) {
      return false;
    }
    let foundScript = false;
    if (node.querySelectorAll) {
      node.querySelectorAll('script').forEach((script) => {
        markDynamicScript(script);
        foundScript = true;
      });
      node.querySelectorAll('iframe').forEach((frame) => queueIframeHook(frame));
    } else {
      foundScript = traverseForSpecialDescendants(node);
    }
    if (foundScript) {
      node.__static_dynamic_script = true;
    }
    return foundScript;
  }

  function attributeTargetsScript(element, name) {
    if (!element || !name || !isScriptNode(element)) {
      return false;
    }
    const lowered = name.toLowerCase();
    return lowered === 'src' || lowered === 'href' || lowered.endsWith(':href');
  }

  function hasGuardForParent(node, parent) {
    if (!node || !parent) {
      return false;
    }
    if (typeof WeakSet === 'function' && node.__static_guard_parents instanceof WeakSet) {
      return node.__static_guard_parents.has(parent);
    }
    if (Array.isArray(node.__static_guard_parent_ids)) {
      return node.__static_guard_parent_ids.indexOf(parent) !== -1;
    }
    return false;
  }

  function recordGuardParent(node, parent) {
    if (!node || !parent) {
      return;
    }
    if (typeof WeakSet === 'function') {
      if (!(node.__static_guard_parents instanceof WeakSet)) {
        node.__static_guard_parents = new WeakSet();
      }
      node.__static_guard_parents.add(parent);
      return;
    }
    if (!Array.isArray(node.__static_guard_parent_ids)) {
      node.__static_guard_parent_ids = [];
    }
    if (node.__static_guard_parent_ids.indexOf(parent) === -1) {
      node.__static_guard_parent_ids.push(parent);
    }
  }

  function injectGuard(beforeNode, parent) {
    if (!parent) {
      return;
    }
    const script = native.createElement.call(document, 'script');
    if (STATE.nonce) {
      script.setAttribute('nonce', STATE.nonce);
    }
    const payload = `;(function(){ if (!window.${MARK}) { console.warn('[STATIC] dynamic script executed before bootstrap'); } })();`;
    script.textContent = STATE.trustedTypes ? STATE.trustedTypes.createScript(payload) : payload;
    const hasRef = beforeNode && beforeNode.parentNode === parent;
    if (hasRef) {
      native.insertBefore.call(parent, script, beforeNode);
    } else {
      native.appendChild.call(parent, script);
    }
  }

  function ensureGuardBeforeExecution(node, parent, refNode) {
    if (!node || !node.__static_dynamic_script || !parent) {
      return;
    }
    if (hasGuardForParent(node, parent)) {
      return;
    }
    injectGuard(refNode, parent);
    recordGuardParent(node, parent);
  }

  window.eval = function guardedEval(payload) {
    if (typeof payload !== 'string') {
      return native.eval.call(this, payload);
    }
    const wrapped = `;(function(){\n${emitBindings()}\nreturn (function(){\n${payload}\n}).call(this);\n}).call(this);`;
    try {
      return native.eval.call(this, wrapped);
    } catch (err) {
      console.warn('[STATIC] eval wrapper fallback:', err.message);
      return native.eval.call(this, payload);
    }
  };
  window.eval.toString = () => 'function eval() { [native code] }';

  window.Function = function guardedFunction() {
    const args = Array.prototype.slice.call(arguments);
    const body = args.length ? String(args[args.length - 1]) : '';
    const params = args.slice(0, -1);
    const wrappedBody = `${emitBindings()}\n${body}`;
    try {
      return native.Function.apply(this, params.concat([wrappedBody]));
    } catch (err) {
      console.warn('[STATIC] Function wrapper fallback:', err.message);
      return native.Function.apply(this, args);
    }
  };
  Object.setPrototypeOf(window.Function, native.Function);
  window.Function.prototype = native.Function.prototype;
  window.Function.toString = () => 'function Function() { [native code] }';

  Document.prototype.createElement = function patchedCreateElement(tag, options) {
    const node = native.createElement.call(this, tag, options);
    trackSpecialNode(node, normalizeTagName(tag));
    return node;
  };

  if (typeof native.createElementNS === 'function') {
    Document.prototype.createElementNS = function patchedCreateElementNS(ns, qualifiedName) {
      const node = native.createElementNS.call(this, ns, qualifiedName);
      const local = qualifiedName ? normalizeTagName(qualifiedName.split(':').pop()) : '';
      trackSpecialNode(node, local);
      return node;
    };
  }

  if (typeof native.adoptNode === 'function') {
    Document.prototype.adoptNode = function patchedAdopt(node) {
      const adopted = native.adoptNode.call(this, node);
      markSubtree(adopted);
      return adopted;
    };
  }

  if (typeof native.importNode === 'function') {
    Document.prototype.importNode = function patchedImport(node, deep) {
      const imported = native.importNode.call(this, node, deep);
      markSubtree(imported);
      return imported;
    };
  }

  Element.prototype.setAttribute = function patchedSetAttribute(name, value) {
    if (attributeTargetsScript(this, name)) {
      markDynamicScript(this);
    }
    return native.setAttribute.call(this, name, value);
  };

  if (typeof native.setAttributeNS === 'function') {
    Element.prototype.setAttributeNS = function patchedSetAttributeNS(ns, name, value) {
      if (attributeTargetsScript(this, name)) {
        markDynamicScript(this);
      }
      return native.setAttributeNS.call(this, ns, name, value);
    };
  }

  Node.prototype.appendChild = function patchedAppend(child) {
    markSubtree(child);
    ensureGuardBeforeExecution(child, this, null);
    return native.appendChild.call(this, child);
  };

  Node.prototype.insertBefore = function patchedInsert(newNode, refNode) {
    markSubtree(newNode);
    ensureGuardBeforeExecution(newNode, this, refNode);
    return native.insertBefore.call(this, newNode, refNode);
  };

  Node.prototype.replaceChild = function patchedReplace(newNode, oldNode) {
    markSubtree(newNode);
    ensureGuardBeforeExecution(newNode, this, oldNode);
    return native.replaceChild.call(this, newNode, oldNode);
  };

  function syncDateAndIntl(targetWin) {
    try {
      if (window.Date && targetWin.Date) {
        const sourceProto = window.Date.prototype;
        const targetProto = targetWin.Date.prototype;
        const dateMethods = ['getTimezoneOffset', 'toString', 'toTimeString', 'toLocaleString'];
        dateMethods.forEach((method) => {
          const impl = sourceProto && sourceProto[method];
          if (typeof impl === 'function' && impl.toString().indexOf('[native code]') === -1) {
            targetProto[method] = impl;
          }
        });
      }
    } catch (err) {
      console.warn('[STATIC] failed to mirror Date prototype:', err.message);
    }

    try {
      if (window.Intl && window.Intl.DateTimeFormat && targetWin.Intl) {
        const impl = window.Intl.DateTimeFormat;
        if (typeof impl === 'function' && impl.toString().indexOf('[native code]') === -1) {
          targetWin.Intl.DateTimeFormat = impl;
        }
      }
    } catch (err) {
      console.warn('[STATIC] failed to mirror Intl.DateTimeFormat:', err.message);
    }
  }

  function mirrorHighEntropyGlobals(targetWin) {
    if (!targetWin) {
      return;
    }
    const descriptors = [
      ['navigator', window.navigator],
      ['screen', window.screen],
      ['performance', window.performance],
    ];
    descriptors.forEach(([key, value]) => {
      if (!value) {
        return;
      }
      try {
        native.defineProperty(targetWin, key, {
          configurable: true,
          enumerable: false,
          get() {
            return value;
          },
        });
      } catch (_) {
        try {
          targetWin[key] = value;
        } catch (_) {}
      }
    });

    ['devicePixelRatio', 'innerWidth', 'innerHeight', 'outerWidth', 'outerHeight'].forEach((prop) => {
      try {
        native.defineProperty(targetWin, prop, {
          configurable: true,
          get() {
            return window[prop];
          },
        });
      } catch (_) {
        try {
          targetWin[prop] = window[prop];
        } catch (_) {}
      }
    });

    if (window.__fpConfig) {
      targetWin.__fpConfig = window.__fpConfig;
    }
    if (window.__STATIC_CONFIG__) {
      targetWin.__STATIC_CONFIG__ = window.__STATIC_CONFIG__;
    }

    syncDateAndIntl(targetWin);
  }

  function propagateIframe(iframe) {
    try {
      if (!(iframe instanceof native.HTMLIFrameElement)) {
        return;
      }
      const targetWin = iframe.contentWindow;
      if (!targetWin || targetWin[MARK]) {
        return;
      }
      targetWin.eval = window.eval;
      targetWin.Function = window.Function;
      targetWin.__404_spoofed_globals = getSpoofedGlobals();
      targetWin.__static_spoofed_globals = getSpoofedGlobals();
      targetWin.__STATIC_CSP_NONCE = STATE.nonce;
      targetWin.__static_bootstrap_parent = true;
      mirrorHighEntropyGlobals(targetWin);
    } catch (err) {
      console.warn('[STATIC] iframe propagation blocked:', err.message);
    }
  }

  function scheduleIframePropagation(iframe) {
    if (!iframe || iframe.__static_bootstrap_iframe_guarded) {
      return;
    }
    iframe.__static_bootstrap_iframe_guarded = true;
    const propagateNow = () => propagateIframe(iframe);
    iframe.addEventListener('load', propagateNow);
    try {
      const doc = iframe.contentDocument;
      if (doc && doc.readyState && doc.readyState !== 'loading') {
        propagateNow();
      }
    } catch (_) {
      /* cross-origin frames are ignored */
    }
  }

  function queueIframeHook(iframe) {
    if (!iframe) {
      return;
    }
    if (typeof queueMicrotask === 'function') {
      queueMicrotask(() => scheduleIframePropagation(iframe));
    } else {
      setTimeout(() => scheduleIframePropagation(iframe), 0);
    }
  }

  function monitorIframeNode(node) {
    if (!node || node.nodeType !== 1) {
      return;
    }
    if (node.tagName === 'IFRAME') {
      scheduleIframePropagation(node);
      return;
    }
    if (typeof node.querySelectorAll === 'function') {
      try {
        node.querySelectorAll('iframe').forEach((iframe) => scheduleIframePropagation(iframe));
      } catch (_) {
        /* ignored */
      }
    }
  }

  function bootstrapExistingIframes() {
    try {
      const frames = document.querySelectorAll ? document.querySelectorAll('iframe') : [];
      frames.forEach((iframe) => scheduleIframePropagation(iframe));
    } catch (_) {
      /* ignored */
    }
  }

  function installFontMetricShim() {
    if (typeof HTMLElement === 'undefined') {
      return;
    }
    const widthDescriptor = native.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    const heightDescriptor = native.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
    if (!widthDescriptor || !heightDescriptor || typeof widthDescriptor.get !== 'function' || typeof heightDescriptor.get !== 'function') {
      return;
    }

    const genericFonts = new Set([
      'monospace',
      'sans-serif',
      'serif',
      'cursive',
      'fantasy',
      'system-ui',
      '-apple-system',
      'blinkmacsystemfont',
      'default',
    ]);

    function deterministicJitter(seed, spread) {
      let hash = 0;
      for (let i = 0; i < seed.length; i++) {
        hash = ((hash << 5) - hash) + seed.charCodeAt(i);
        hash |= 0;
      }
      const range = spread * 2 + 1;
      const offset = ((hash % range) + range) % range;
      return offset - spread;
    }

    let cachedFontKey = '';
    let cachedFontSet = new Set();

    function collectProfileFonts() {
      const config = window.__fpConfig || (window.__STATIC_CONFIG__ && window.__STATIC_CONFIG__.fingerprint) || {};
      const fonts = Array.isArray(config.fonts) ? config.fonts : [];
      const key = fonts.join('|');
      if (key !== cachedFontKey) {
        cachedFontKey = key;
        cachedFontSet = new Set(fonts.map((font) => font.toLowerCase()));
      }
      return cachedFontSet;
    }

    function fallbackMeasure(element, getter, fontFamily) {
      if (!element || !element.style || typeof getter !== 'function') {
        return getter.call(element);
      }
      const previous = element.style.fontFamily;
      element.style.fontFamily = fontFamily;
      const value = getter.call(element);
      element.style.fontFamily = previous;
      return value;
    }

    function normalizeMetric(element, realValue, isWidth) {
      if (!element || !element.style) {
        return realValue;
      }
      const rawFamily = element.style.fontFamily || '';
      const fontFamily = rawFamily.replace(/["']/g, '').split(',')[0].trim().toLowerCase();
      if (!fontFamily) {
        return realValue;
      }
      const textSeed = element.textContent || '';
      if (genericFonts.has(fontFamily)) {
        const base = isWidth ? 800 : 1600;
        return base + deterministicJitter(`${fontFamily}:${textSeed}:${isWidth ? 'w' : 'h'}`, 50);
      }
      const profileFonts = collectProfileFonts();
      if (!profileFonts.size || !profileFonts.has(fontFamily)) {
        return fallbackMeasure(element, isWidth ? widthDescriptor.get : heightDescriptor.get, 'monospace');
      }
      const jitter = deterministicJitter(`${fontFamily}:${textSeed}:${isWidth ? 'w' : 'h'}`, 8);
      const candidate = realValue + jitter;
      return candidate > 0 ? candidate : realValue;
    }

    native.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      configurable: true,
      enumerable: widthDescriptor.enumerable,
      get() {
        const realWidth = widthDescriptor.get.call(this);
        return normalizeMetric(this, realWidth, true);
      },
    });

    native.defineProperty(HTMLElement.prototype, 'offsetHeight', {
      configurable: true,
      enumerable: heightDescriptor.enumerable,
      get() {
        const realHeight = heightDescriptor.get.call(this);
        return normalizeMetric(this, realHeight, false);
      },
    });
  }

  if (window.MutationObserver) {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => monitorIframeNode(node));
      }
    });
    observer.observe(document.documentElement || document.body, { childList: true, subtree: true });
  }

  bootstrapExistingIframes();
  installFontMetricShim();

  function sanitizeStacks() {
    const descriptor = native.getOwnPropertyDescriptor(Error.prototype, 'stack');
    if (!descriptor || !descriptor.get) {
      return;
    }
    const original = descriptor.get;
    native.defineProperty(Error.prototype, 'stack', {
      configurable: true,
      get() {
        let stack = original.call(this);
        if (typeof stack === 'string') {
          const scrubTokens = [
            'staticBootstrap',
            'emitBindings',
            'guardedFunction',
            'guardedEval',
            'queueIframeHook',
            'ensureGuardBeforeExecution',
            '__static',
            '__404',
          ];
          stack = stack
            .split('\n')
            .filter((line) => !scrubTokens.some((token) => line.indexOf(token) !== -1))
            .join('\n');
        }
        return stack;
      },
    });
  }
  sanitizeStacks();

  if (scriptGuardsEnabled) {
    try {
      Object.defineProperty(window, 'eval', { value: window.eval, configurable: false, writable: false });
      Object.defineProperty(window, 'Function', { value: window.Function, configurable: false, writable: false });
    } catch (err) {
      console.warn('[STATIC] failed to lock globals:', err.message);
    }
  }

  window[MARK] = true;
  window.__404_bootstrap_active = true;
  window.__static_bootstrap_nonce = STATE.nonce;
  console.log('[STATIC] bootstrap ready');
})();
