/* STATIC Proxy Fingerprint Spoofing Layer v4 (AGPL-3.0) */
(function staticFingerprintShield() {
  'use strict';

  if (window.__static_advanced_protections_active || window.__404_advanced_protections_active) {
    return;
  }

  if (!window.__static_config_ready && !window.__404_config_ready) {
    console.error('[STATIC-FP] config not ready; aborting spoof stack');
    return;
  }

  function getConfig() {
    const raw = window.__STATIC_CONFIG__ || window.__fpConfig || window.__STATIC_FINGERPRINT__ || {};
    if (raw && typeof raw === 'object' && raw.fingerprint && typeof raw.fingerprint === 'object') {
      return raw.fingerprint;
    }
    if (window.__STATIC_FINGERPRINT__ && typeof window.__STATIC_FINGERPRINT__ === 'object') {
      return window.__STATIC_FINGERPRINT__;
    }
    return raw;
  }

  const config = getConfig();
  const debug = Boolean(config.debug);
  const enableDrift = config.enable_fingerprint_drift !== false;
  const canvasNoise = normalizeCanvasNoise(config.canvas_noise || {});
  const canvasStrategy = cloneCanvasStrategy(canvasNoise.strategy);
  if (canvasStrategy) {
    window.__static_canvas_strategy = canvasStrategy;
  }

  function localHash(input) {
    let h = 0;
    const text = String(input || 'static');
    for (let i = 0; i < text.length; i += 1) {
      h = ((h << 5) - h) + text.charCodeAt(i);
      h |= 0;
    }
    return Math.abs(h).toString(16);
  }

  function localRng(seed) {
    let state = 0;
    const text = String(seed || 'static-seed');
    for (let i = 0; i < text.length; i += 1) {
      state = ((state << 5) - state) + text.charCodeAt(i);
      state |= 0;
    }
    state = state >>> 0 || 1;
    return function rand() {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) / 0x100000000;
    };
  }

  function ensureSessionId(driftEnabled) {
    if (window.__STATIC_SESSION_ID) {
      if (!driftEnabled) {
        window.__STATIC_SESSION_ID = 'static';
        window.__404_session_id = 'static';
      }
      return window.__STATIC_SESSION_ID;
    }
    if (!driftEnabled) {
      window.__STATIC_SESSION_ID = 'static';
      window.__404_session_id = 'static';
      return 'static';
    }
    const entropy = `${Date.now().toString(36)}:${Math.random().toString(16).slice(2)}:${performance.now().toString(16)}`;
    const hash = (window.__static_hash || localHash)(entropy);
    window.__STATIC_SESSION_ID = hash;
    window.__404_session_id = hash;
    return hash;
  }

  const rngFactory = typeof window.__static_rng === 'function' ? window.__static_rng : localRng;
  const hashFn = typeof window.__static_hash === 'function' ? window.__static_hash : localHash;
  const sessionId = ensureSessionId(enableDrift);
  const sessionCanvasKey = buildSessionCanvasKey(config.canvas_hash, sessionId, enableDrift);
  const displayCanvasFingerprint = generateMD5StyleHash(sessionCanvasKey);

  function scopedSeed(label, source) {
    return `${label}:${source}:${sessionId}`;
  }

  function clampCanvasByte(value) {
    if (value < 0) {
      return 0;
    }
    if (value > 255) {
      return 255;
    }
    return value;
  }

  function injectCanvasNoise(imageData) {
    if (!imageData || !imageData.data) {
      return;
    }

    const noiseSeed = hashString(`${sessionCanvasKey}:${imageData.width}x${imageData.height}`);
    let state = noiseSeed;
    function noise() {
      state |= 0;
      state = (state + 0x6D2B79F5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    const data = imageData.data;
    const stride = imageData.width <= canvasNoise.small_canvas_threshold && imageData.height <= canvasNoise.small_canvas_threshold
      ? canvasNoise.small_canvas_stride
      : canvasNoise.default_stride;
    let modified = 0;

    for (let i = 0; i < data.length; i += stride) {
      if (noise() >= canvasNoise.noise_probability) {
        continue;
      }

      const deltaMagnitude = canvasNoise.delta_min + (canvasNoise.delta_max - canvasNoise.delta_min) * noise();
      const signedDelta = (noise() > 0.5 ? 1 : -1) * deltaMagnitude;
      const delta = canvasNoise.integer_delta ? Math.round(signedDelta) : signedDelta;

      data[i] = clampCanvasByte(data[i] + delta);
      if ((i + 1) < data.length) data[i + 1] = clampCanvasByte(data[i + 1] + delta);
      if ((i + 2) < data.length) data[i + 2] = clampCanvasByte(data[i + 2] + delta);
      if (canvasNoise.touch_alpha && (i + 3) < data.length) {
        data[i + 3] = clampCanvasByte(data[i + 3] + delta);
      }
      modified += 1;
    }

    if (debug && canvasNoise.log_activity) {
      console.debug('[STATIC-FP] canvas noise applied', modified, 'pixels');
    }
  }

  function applyNoiseToCanvasSurface(scope, canvasLike) {
    if (!canvasLike || typeof canvasLike.getContext !== 'function') {
      return;
    }
    const ctx = canvasLike.getContext('2d');
    if (!ctx || typeof ctx.getImageData !== 'function' || typeof ctx.putImageData !== 'function') {
      return;
    }
    try {
      const data = ctx.getImageData(0, 0, canvasLike.width, canvasLike.height);
      injectCanvasNoise(data);
      ctx.putImageData(data, 0, 0);
    } catch (_) {
      /* ignored */
    }
  }

  function deterministicId(prefix, key) {
    const hash = hashFn(`${prefix}:${key}`);
    return `${prefix}-${hash.slice(0, 12)}`;
  }

  function resolveProfileDevice(kind, idx) {
    if (!Array.isArray(config.media_devices)) {
      return null;
    }
    const byKind = config.media_devices.find((entry) => entry && entry.kind === kind);
    if (byKind) {
      return byKind;
    }
    return config.media_devices[idx] || null;
  }

  applyDeviceSpoof(window);
  applyCanvasSpoof(window);
  applyWebGLSpoof(window);
  applyAudioSpoof(window);
  applyOffscreenCanvasSpoof(window);
  applyExtendedAudioGraphSpoof(window);
  applyWebRTCSpoof(window);
  applyMediaDevicesSpoof(window);
  applyGamepadSpoof(window);
  applySpeechSynthesisSpoof(window);
  applyEventTimingSpoof(window);
  // applyMathNoise(window); // temporarily disabled for captcha stability
  applyWebGpuSpoof(window);
  applyAutomationEvasion(window);
  applyGeolocationSpoof(window);
  setupIframePropagation();

  window.__static_advanced_protections_active = true;
  window.__404_advanced_protections_active = true;
  window.__static_advanced_protections_version = '3.0.0';
  window.__404_advanced_protections_version = '3.0.0';

  if (debug) {
    console.info('[STATIC-FP] canvas/webgl/audio protections enabled');
  }

  function ensureLegacyCanvasFingerprintScope(scope) {
    if (scope.__404_canvas_fingerprint === displayCanvasFingerprint) {
      return;
    }
    try {
      Object.defineProperty(scope, '__404_canvas_fingerprint', {
        value: displayCanvasFingerprint,
        writable: false,
        enumerable: false,
        configurable: false,
      });
    } catch (_) {
      scope.__404_canvas_fingerprint = displayCanvasFingerprint;
    }
  }

  function applyCanvasSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (config.enable_canvas_spoof === false) {
      return;
    }
    if (!scope.HTMLCanvasElement || !scope.CanvasRenderingContext2D) {
      return;
    }

    if (canvasStrategy) {
      try {
        scope.__static_canvas_strategy = cloneCanvasStrategy(canvasStrategy);
      } catch (_) {
        scope.__static_canvas_strategy = canvasStrategy;
      }
    }

    scope.__static_canvas_noise_handler = function canvasNoiseBridge(details) {
      if (!details || !details.imageData) {
        return false;
      }
      const executor = scope.__static_canvas_plan_executor || window.__static_canvas_plan_executor;
      if (typeof executor === 'function' && details.plan) {
        try {
          executor(details, details.plan);
          return true;
        } catch (err) {
          if (debug) {
            console.warn('[STATIC-FP] canvas plan executor error', err);
          }
        }
      }
      injectCanvasNoise(details.imageData);
      return true;
    };
    ensureLegacyCanvasFingerprintScope(scope);

    if (scope.__static_fp_canvas_applied) {
      return;
    }
    scope.__static_fp_canvas_applied = true;

    if (scope.HTMLCanvasElement.prototype.__static_canvas_guarded) {
      return;
    }

    const originalToDataURL = scope.HTMLCanvasElement.prototype.toDataURL;
    const originalToBlob = scope.HTMLCanvasElement.prototype.toBlob;
    const originalGetImageData = scope.CanvasRenderingContext2D.prototype.getImageData;

    scope.CanvasRenderingContext2D.prototype.getImageData = function patchedGetImageData(sx, sy, sw, sh) {
      const data = originalGetImageData.call(this, sx, sy, sw, sh);
      injectCanvasNoise(data);
      return data;
    };

    scope.HTMLCanvasElement.prototype.toDataURL = function patchedToDataURL() {
      applyNoiseToCanvasSurface(scope, this);
      return originalToDataURL.apply(this, arguments);
    };

    scope.HTMLCanvasElement.prototype.toBlob = function patchedToBlob(callback) {
      applyNoiseToCanvasSurface(scope, this);
      return originalToBlob.call(this, callback, arguments[1], arguments[2]);
    };
  }

  function applyWebGLSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (config.enable_webgl_spoof === false) {
      return;
    }
    if (!scope.HTMLCanvasElement) {
      return;
    }
    if (scope.__static_fp_webgl_applied) {
      return;
    }
    scope.__static_fp_webgl_applied = true;

    const originalGetContext = scope.HTMLCanvasElement.prototype.getContext;
    const vendor = config.webgl_vendor || 'Intel Inc.';
    const renderer = config.webgl_renderer || 'Intel(R) UHD Graphics 770';
    const DEBUG_VENDOR_ENUM = 0x9245;
    const DEBUG_RENDERER_ENUM = 0x9246;

    scope.HTMLCanvasElement.prototype.getContext = function patchedGetContext(type, attributes) {
      const context = originalGetContext.call(this, type, attributes);
      if (!context || !type || typeof type !== 'string') {
        return context;
      }

      const kind = type.toLowerCase();
      if (kind !== 'webgl' && kind !== 'experimental-webgl' && kind !== 'webgl2') {
        return context;
      }

      if (context.__static_device_proxy) {
        return context.__static_device_proxy;
      }

      const proxy = new Proxy(context, {
        get(target, prop) {
          if (prop === '__static_device_proxy') {
            return proxy;
          }
          if (prop === 'getParameter') {
            return function patchedGetParameter(parameter) {
              const overrides = ensureWebGLOverrides(target);
              const resolved = typeof parameter === 'number' ? parameter : Number(parameter);
              if (resolved === DEBUG_VENDOR_ENUM || parameter === target.UNMASKED_VENDOR_WEBGL) {
                return vendor;
              }
              if (resolved === DEBUG_RENDERER_ENUM || parameter === target.UNMASKED_RENDERER_WEBGL) {
                return renderer;
              }
              const entry = overrides.get(resolved);
              if (entry) {
                return materializeParamValue(entry);
              }
              return target.getParameter.call(target, parameter);
            };
          }
          if (prop === 'getExtension') {
            return function patchedGetExtension(name) {
              const ext = target.getExtension ? target.getExtension.call(target, name) : null;
              if (!ext || name !== 'WEBGL_debug_renderer_info') {
                return ext;
              }
              return new Proxy(ext, {
                get(extTarget, extProp) {
                  if (extProp === 'UNMASKED_VENDOR_WEBGL') {
                    return DEBUG_VENDOR_ENUM;
                  }
                  if (extProp === 'UNMASKED_RENDERER_WEBGL') {
                    return DEBUG_RENDERER_ENUM;
                  }
                  const value = Reflect.get(extTarget, extProp);
                  return typeof value === 'function' ? value.bind(extTarget) : value;
                },
              });
            };
          }
          if (prop === 'getSupportedExtensions') {
            return function patchedGetSupportedExtensions() {
              const list = target.getSupportedExtensions ? target.getSupportedExtensions.call(target) : [];
              return Array.isArray(list) ? list.slice() : list;
            };
          }
          const value = Reflect.get(target, prop);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });

      Object.defineProperty(context, '__static_device_proxy', {
        value: proxy,
        writable: false,
        configurable: false,
        enumerable: false,
      });

      return proxy;
    };

    function ensureWebGLOverrides(gl) {
      if (gl.__static_param_overrides) {
        return gl.__static_param_overrides;
      }
      const map = buildWebGLParameterMap(gl, config);
      Object.defineProperty(gl, '__static_param_overrides', {
        value: map,
        writable: false,
        configurable: false,
        enumerable: false,
      });
      return map;
    }
  }

  function applyDeviceSpoof(targetWindow) {
    const scope = targetWindow || window;
    const nav = scope.navigator;
    if (!nav) {
      return;
    }

    const browserType = config.browser_type || config.browserType || 'chrome';
    const vendorValue = resolveVendorValue(browserType);
    const vendorFlavors = resolveVendorFlavors(browserType);
    const targets = [nav];
    const proto = Object.getPrototypeOf(nav);
    if (proto && proto !== Object.prototype) {
      targets.push(proto);
    }

    defineNavigatorOverride(targets, 'hardwareConcurrency', config.hardware_concurrency);
    defineNavigatorOverride(targets, 'deviceMemory', config.device_memory);
    defineNavigatorOverride(targets, 'maxTouchPoints', config.max_touch_points);
    defineNavigatorOverride(targets, 'platform', config.platform);
    defineNavigatorOverride(targets, 'vendor', vendorValue);

    if (vendorFlavors === null) {
      removeNavigatorProperty(targets, 'vendorFlavors');
    } else if (vendorFlavors !== undefined) {
      defineNavigatorOverride(targets, 'vendorFlavors', vendorFlavors);
    }
  }

  function applyOffscreenCanvasSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (config.enable_canvas_spoof === false) {
      return;
    }
    if (scope.__static_fp_offscreen_canvas_applied) {
      return;
    }
    scope.__static_fp_offscreen_canvas_applied = true;

    const guardActive = Boolean(scope.HTMLCanvasElement
      && scope.HTMLCanvasElement.prototype
      && scope.HTMLCanvasElement.prototype.__static_canvas_guarded);

    const Offscreen = scope.OffscreenCanvas;
    if (typeof Offscreen === 'function' && Offscreen.prototype) {
      const offscreenProto = Offscreen.prototype;
      if (!guardActive && typeof offscreenProto.convertToBlob === 'function') {
        const originalConvertToBlob = offscreenProto.convertToBlob;
        offscreenProto.convertToBlob = function patchedConvertToBlob() {
          applyNoiseToCanvasSurface(scope, this);
          return originalConvertToBlob.apply(this, arguments);
        };
      }
      if (!guardActive && typeof offscreenProto.transferToImageBitmap === 'function') {
        const originalTransfer = offscreenProto.transferToImageBitmap;
        offscreenProto.transferToImageBitmap = function patchedTransferToImageBitmap() {
          applyNoiseToCanvasSurface(scope, this);
          return originalTransfer.apply(this, arguments);
        };
      }
    }

    if (typeof scope.createImageBitmap === 'function' && !scope.__static_fp_imagebitmap_applied) {
      scope.__static_fp_imagebitmap_applied = true;
      const originalCreateImageBitmap = scope.createImageBitmap.bind(scope);
      scope.createImageBitmap = function patchedCreateImageBitmap(source) {
        try {
          if (source && typeof source === 'object' && 'width' in source && 'height' in source && typeof source.width === 'number') {
            applyNoiseToCanvasSurface(scope, source);
          }
        } catch (_) {
          /* ignored */
        }
        return originalCreateImageBitmap.apply(scope, arguments);
      };
    }
  }

  function applyAudioSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (config.enable_audio_spoof === false) {
      return;
    }
    if (scope.__static_fp_audio_applied) {
      return;
    }
    scope.__static_fp_audio_applied = true;

    const Offline = scope.OfflineAudioContext || scope.webkitOfflineAudioContext;
    if (Offline && Offline.prototype.startRendering) {
      const originalStartRendering = Offline.prototype.startRendering;
      Offline.prototype.startRendering = function patchedStartRendering() {
        const promise = originalStartRendering.apply(this, arguments);
        return promise.then((buffer) => {
          try {
            const rng = rngFactory(scopedSeed('audio-buffer', config.audio_hash || 'static'));
            for (let channel = 0; channel < buffer.numberOfChannels; channel += 1) {
              const data = buffer.getChannelData(channel);
              for (let i = 0; i < data.length; i += 1) {
                data[i] += (rng() - 0.5) * 1e-4;
              }
            }
          } catch (_) {
            /* ignored */
          }
          return buffer;
        });
      };
    }

    const Base = scope.BaseAudioContext || scope.AudioContext || scope.webkitAudioContext;
    if (Base && Base.prototype.createOscillator) {
      const originalCreateOscillator = Base.prototype.createOscillator;
      Base.prototype.createOscillator = function patchedCreateOscillator() {
        const osc = originalCreateOscillator.apply(this, arguments);
        const rng = rngFactory(scopedSeed('audio-osc', config.audio_hash || 'static'));
        const nativeStart = osc.start;
        osc.start = function patchedStart(when) {
          const detune = (rng() - 0.5) * 0.6;
          try {
            if (osc.frequency && typeof osc.frequency.setValueAtTime === 'function') {
              const base = osc.frequency.value || 440;
              osc.frequency.setValueAtTime(base + detune, when || 0);
            }
          } catch (_) {
            /* ignored */
          }
          return nativeStart.apply(this, arguments);
        };
        return osc;
      };
    }
  }

  function scrubAudioBuffer(payload, rng) {
    if (!payload || typeof rng !== 'function') {
      return;
    }
    const inject = (arr) => {
      if (!arr || typeof arr.length !== 'number') {
        return;
      }
      for (let i = 0; i < arr.length; i += 1) {
        arr[i] += (rng() - 0.5) * 1e-4;
      }
    };
    if (ArrayBuffer.isView(payload)) {
      inject(payload);
      return;
    }
    if (Array.isArray(payload)) {
      payload.forEach((entry) => inject(entry));
      return;
    }
    if (payload && Array.isArray(payload.channelData)) {
      payload.channelData.forEach((entry) => inject(entry));
    }
  }

  function applyExtendedAudioGraphSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (scope.__static_fp_audio_graph_applied) {
      return;
    }
    scope.__static_fp_audio_graph_applied = true;

    const analyserMap = new WeakMap();
    let analyserCounter = 0;
    const Analyser = scope.AnalyserNode;
    if (Analyser && Analyser.prototype && typeof Analyser.prototype.getFloatFrequencyData === 'function') {
      const originalGetFloat = Analyser.prototype.getFloatFrequencyData;
      Analyser.prototype.getFloatFrequencyData = function patchedGetFloatFrequencyData(array) {
        const result = originalGetFloat.call(this, array);
        try {
          let rng = analyserMap.get(this);
          if (!rng) {
            rng = rngFactory(scopedSeed('audio-analyser', `${config.audio_hash || 'static'}:${analyserCounter}`));
            analyserCounter += 1;
            analyserMap.set(this, rng);
          }
          scrubAudioBuffer(array, rng);
        } catch (_) {
          /* ignored */
        }
        return result;
      };
    }

    const workletPortRng = new WeakMap();
    function wrapAudioWorkletPort(port, label) {
      if (!port || port.__static_fp_wrapped) {
        return;
      }
      const rng = rngFactory(scopedSeed('audio-worklet', label || 'port'));
      workletPortRng.set(port, rng);
      port.__static_fp_wrapped = true;
      if (typeof port.postMessage === 'function') {
        const originalPost = port.postMessage.bind(port);
        port.postMessage = function patchedPostMessage(message, transfer) {
          scrubAudioBuffer(message, workletPortRng.get(port));
          return originalPost(message, transfer);
        };
      }
      if (typeof port.addEventListener === 'function') {
        const originalAdd = port.addEventListener.bind(port);
        port.addEventListener = function patchedAddEventListener(type, listener, options) {
          if (type === 'message' && typeof listener === 'function') {
            const wrapped = function wrappedMessage(event) {
              scrubAudioBuffer(event && event.data, workletPortRng.get(port));
              return listener.call(this, event);
            };
            return originalAdd(type, wrapped, options);
          }
          return originalAdd(type, listener, options);
        };
      }
    }

    const AudioWorkletNodeCtor = scope.AudioWorkletNode;
    if (AudioWorkletNodeCtor && AudioWorkletNodeCtor.prototype) {
      const portDescriptor = Object.getOwnPropertyDescriptor(AudioWorkletNodeCtor.prototype, 'port');
      if (portDescriptor && typeof portDescriptor.get === 'function') {
        Object.defineProperty(AudioWorkletNodeCtor.prototype, 'port', {
          configurable: true,
          enumerable: portDescriptor.enumerable,
          get() {
            const port = portDescriptor.get.call(this);
            wrapAudioWorkletPort(port, this && this.constructor ? this.constructor.name : 'AudioWorkletNode');
            return port;
          },
        });
      }
    }
  }

  const PRIVATE_IPV4 = /^(0\.|10\.|127\.|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)/;
  const PRIVATE_IPV6 = /^(::1|fc00:|fd00:|fe80:)/i;

  function sanitizeCandidateLine(line, publicIpv4, publicIpv6) {
    if (typeof line !== 'string') {
      return line;
    }
    const trimmed = line.trim();
    const hasPrefix = trimmed.startsWith('a=');
    const payload = hasPrefix ? trimmed.slice(2) : trimmed;
    const parts = payload.split(' ');
    if (parts.length < 8) {
      return trimmed;
    }
    const ipIndex = 4;
    const typeIndex = parts.indexOf('typ');
    const ip = parts[ipIndex];
    if (PRIVATE_IPV4.test(ip)) {
      parts[ipIndex] = publicIpv4;
    } else if (PRIVATE_IPV6.test(ip)) {
      parts[ipIndex] = publicIpv6;
    }
    if (typeIndex >= 0 && parts[typeIndex + 1] === 'host' && (PRIVATE_IPV4.test(ip) || PRIVATE_IPV6.test(ip))) {
      parts[typeIndex + 1] = 'srflx';
    }
    if (config.webrtc_udp_only === true) {
      parts[2] = 'udp';
    }
    const sanitized = parts.join(' ');
    return hasPrefix ? `a=${sanitized}` : sanitized;
  }

  function sanitizeSessionDescription(scope, description, limit, publicIpv4, publicIpv6) {
    if (!description || !description.sdp) {
      return description;
    }
    const lines = String(description.sdp).split(/\r?\n/);
    let candidates = 0;
    const sanitizedLines = lines.filter((line) => {
      if (!line || !line.startsWith('a=candidate')) {
        return true;
      }
      if (candidates >= limit) {
        return false;
      }
      candidates += 1;
      return true;
    }).map((line) => {
      if (!line) {
        return line;
      }
      if (line.startsWith('a=candidate')) {
        return sanitizeCandidateLine(line, publicIpv4, publicIpv6);
      }
      if (line.startsWith('c=IN IP4')) {
        return `c=IN IP4 ${publicIpv4}`;
      }
      if (line.startsWith('c=IN IP6')) {
        return `c=IN IP6 ${publicIpv6}`;
      }
      return line;
    });
    const nextSdp = sanitizedLines.join('\r\n');
    if (nextSdp === description.sdp) {
      return description;
    }
    if (typeof scope.RTCSessionDescription === 'function') {
      try {
        return new scope.RTCSessionDescription({ type: description.type, sdp: nextSdp });
      } catch (_) {
        /* ignored */
      }
    }
    return { type: description.type, sdp: nextSdp };
  }

  function applyWebRTCSpoof(targetWindow) {
    const scope = targetWindow || window;
    const Peer = scope.RTCPeerConnection || scope.webkitRTCPeerConnection;
    if (!Peer || Peer.prototype.__static_fp_webrtc_applied) {
      return;
    }
    Peer.prototype.__static_fp_webrtc_applied = true;

    const candidateLimit = Math.max(1, Number(config.webrtc_candidate_limit) || 4);
    const publicIpv4 = config.webrtc_ip || config.ip_address || '104.244.72.1';
    const publicIpv6 = config.webrtc_ipv6 || '2001:4860:4860::8888';
    const candidateCounter = new WeakMap();
    const listenerMap = new WeakMap();

    function sanitizeCandidateObject(candidate) {
      if (!candidate || typeof candidate.candidate !== 'string') {
        return candidate;
      }
      const sanitizedLine = sanitizeCandidateLine(candidate.candidate, publicIpv4, publicIpv6);
      if (!sanitizedLine) {
        return null;
      }
      if (sanitizedLine === candidate.candidate) {
        return candidate;
      }
      if (typeof scope.RTCIceCandidate === 'function') {
        try {
          return new scope.RTCIceCandidate({
            candidate: sanitizedLine,
            sdpMid: candidate.sdpMid || null,
            sdpMLineIndex: candidate.sdpMLineIndex,
          });
        } catch (_) {
          /* ignored */
        }
      }
      return Object.assign({}, candidate, { candidate: sanitizedLine });
    }

    function processIceCandidateEvent(peer, event) {
      if (!event || !event.candidate) {
        return true;
      }
      const sanitizedCandidate = sanitizeCandidateObject(event.candidate);
      if (!sanitizedCandidate) {
        return false;
      }
      const nextCount = (candidateCounter.get(peer) || 0) + 1;
      if (nextCount > candidateLimit) {
        return false;
      }
      candidateCounter.set(peer, nextCount);
      if (sanitizedCandidate !== event.candidate) {
        try {
          event.candidate = sanitizedCandidate;
        } catch (_) {
          Object.defineProperty(event, 'candidate', {
            value: sanitizedCandidate,
            configurable: true,
          });
        }
      }
      return true;
    }

    const originalAddEvent = Peer.prototype.addEventListener;
    Peer.prototype.addEventListener = function patchedAddEventListener(type, listener, options) {
      if (type === 'icecandidate' && typeof listener === 'function') {
        let wrapped = listenerMap.get(listener);
        if (!wrapped) {
          wrapped = function wrappedIceEvent(event) {
            if (!processIceCandidateEvent(this, event)) {
              return;
            }
            return listener.call(this, event);
          };
          listenerMap.set(listener, wrapped);
        }
        return originalAddEvent.call(this, type, wrapped, options);
      }
      return originalAddEvent.apply(this, arguments);
    };

    const originalRemoveEvent = Peer.prototype.removeEventListener;
    Peer.prototype.removeEventListener = function patchedRemoveEventListener(type, listener, options) {
      if (type === 'icecandidate' && typeof listener === 'function') {
        const wrapped = listenerMap.get(listener) || listener;
        return originalRemoveEvent.call(this, type, wrapped, options);
      }
      return originalRemoveEvent.apply(this, arguments);
    };

    const descriptor = Object.getOwnPropertyDescriptor(Peer.prototype, 'onicecandidate');
    if (descriptor && typeof descriptor.set === 'function') {
      Object.defineProperty(Peer.prototype, 'onicecandidate', {
        configurable: true,
        enumerable: descriptor.enumerable,
        get() {
          return this.__static_fp_onice_original || null;
        },
        set(handler) {
          this.__static_fp_onice_original = handler;
          if (typeof handler !== 'function') {
            return descriptor.set.call(this, handler);
          }
          const wrapped = (event) => {
            if (!processIceCandidateEvent(this, event)) {
              return;
            }
            return handler.call(this, event);
          };
          this.__static_fp_onice_wrapped = wrapped;
          return descriptor.set.call(this, wrapped);
        },
      });
    }

    const originalSetLocalDescription = Peer.prototype.setLocalDescription;
    if (typeof originalSetLocalDescription === 'function') {
      Peer.prototype.setLocalDescription = function patchedSetLocalDescription(description) {
        const sanitized = sanitizeSessionDescription(scope, description || this.localDescription, candidateLimit, publicIpv4, publicIpv6);
        return originalSetLocalDescription.call(this, sanitized);
      };
    }

    const originalCreateOffer = Peer.prototype.createOffer;
    if (typeof originalCreateOffer === 'function') {
      Peer.prototype.createOffer = function patchedCreateOffer(options) {
        return originalCreateOffer.call(this, options).then((desc) => sanitizeSessionDescription(scope, desc, candidateLimit, publicIpv4, publicIpv6));
      };
    }

    const originalCreateAnswer = Peer.prototype.createAnswer;
    if (typeof originalCreateAnswer === 'function') {
      Peer.prototype.createAnswer = function patchedCreateAnswer(options) {
        return originalCreateAnswer.call(this, options).then((desc) => sanitizeSessionDescription(scope, desc, candidateLimit, publicIpv4, publicIpv6));
      };
    }
  }

  function applyMediaDevicesSpoof(targetWindow) {
    const scope = targetWindow || window;
    const nav = scope.navigator;
    if (!nav || !nav.mediaDevices || typeof nav.mediaDevices.enumerateDevices !== 'function') {
      return;
    }
    if (nav.mediaDevices.__static_fp_enumerate_patched) {
      return;
    }
    nav.mediaDevices.__static_fp_enumerate_patched = true;
    const originalEnumerate = nav.mediaDevices.enumerateDevices.bind(nav.mediaDevices);
    function cloneMediaDevice(device, idx) {
      const source = (device && typeof device === 'object') ? device : {};
      const profile = resolveProfileDevice(source.kind, idx) || {};
      const kind = source.kind || profile.kind || 'audioinput';
      const referenceLabel = source.label || profile.label || '';
      const key = `${kind}:${referenceLabel || 'unknown'}:${idx}:${sessionId}`;
      const spoofedId = deterministicId('device', key);
      const groupId = deterministicId('group', key);
      const payload = {
        deviceId: spoofedId,
        groupId,
        kind,
        label: source.label ? (profile.label || source.label) : (profile.label || ''),
      };

      const optionalKeys = ['facingMode', 'vendorId', 'productId'];
      optionalKeys.forEach((prop) => {
        if (Object.prototype.hasOwnProperty.call(profile, prop)) {
          payload[prop] = profile[prop];
        } else if (Object.prototype.hasOwnProperty.call(source, prop)) {
          payload[prop] = source[prop];
        }
      });

      return Object.freeze(payload);
    }

    nav.mediaDevices.enumerateDevices = function patchedEnumerateDevices() {
      return Promise.resolve(originalEnumerate.apply(this, arguments)).then((devices) => {
        if (!Array.isArray(devices)) {
          return devices;
        }
        return devices.map((device, idx) => cloneMediaDevice(device, idx));
      });
    };
  }

  function applyGamepadSpoof(targetWindow) {
    const scope = targetWindow || window;
    const nav = scope.navigator;
    if (!nav || typeof nav.getGamepads !== 'function' || nav.__static_fp_gamepad_patched) {
      return;
    }
    nav.__static_fp_gamepad_patched = true;
    const originalGetGamepads = nav.getGamepads.bind(nav);
    const snapshotCache = new WeakMap();

    function cloneGamepad(pad, idx) {
      const source = (pad && typeof pad === 'object') ? pad : {};
      if (snapshotCache.has(source)) {
        return snapshotCache.get(source);
      }
      const key = `${source.id || 'gamepad'}:${idx}:${sessionId}`;
      const spoofedId = `Static-${hashFn(key).slice(0, 10)}`;
      const rawAxes = source.axes;
      const axes = Array.isArray(rawAxes)
        ? rawAxes.slice()
        : (rawAxes && typeof rawAxes.length === 'number' ? Array.from(rawAxes) : []);
      const rawButtons = source.buttons;
      const buttons = Array.isArray(rawButtons)
        ? rawButtons
        : (rawButtons && typeof rawButtons.length === 'number' ? Array.from(rawButtons) : []);
      const normalizedButtons = buttons.map((btn) => Object.freeze({
          pressed: Boolean(btn && btn.pressed),
          touched: Boolean(btn && btn.touched),
          value: typeof (btn && btn.value) === 'number' ? btn.value : 0,
        }));

      const snapshot = Object.freeze({
        id: spoofedId,
        index: typeof source.index === 'number' ? source.index : idx,
        mapping: source.mapping || 'standard',
        connected: source.connected !== false,
        timestamp: typeof source.timestamp === 'number' ? source.timestamp : Date.now(),
        axes: Object.freeze(axes.map((value) => (Number.isFinite(value) ? value : 0))),
        buttons: Object.freeze(normalizedButtons),
        hand: source.hand || 'unknown',
      });

      snapshotCache.set(source, snapshot);
      return snapshot;
    }

    nav.getGamepads = function patchedGetGamepads() {
      const pads = originalGetGamepads.apply(this, arguments);
      if (!pads) {
        return pads;
      }
      return Array.prototype.map.call(pads, (pad, idx) => cloneGamepad(pad, idx));
    };
  }

  function applySpeechSynthesisSpoof(targetWindow) {
    const scope = targetWindow || window;
    const synth = scope.speechSynthesis;
    if (!synth || synth.__static_fp_speech_patched) {
      return;
    }
    const languages = Array.isArray(config.languages) ? config.languages : (typeof config.languages === 'string' ? config.languages.split(',') : []);
    const primaryLang = (languages[0] || 'en-US').trim() || 'en-US';
    const profileVoices = Array.isArray(config.speech_voices) ? config.speech_voices : [];
    const baseVoices = profileVoices.length ? profileVoices : [
      { name: 'Google US English', lang: primaryLang, localService: true, default: true, voiceURI: 'Google US English' },
    ];
    const voices = baseVoices.map((voice, idx) => Object.freeze({
      default: Boolean(voice.default && idx === 0),
      lang: voice.lang || primaryLang,
      localService: voice.localService !== false,
      name: voice.name || `Static Voice ${idx + 1}`,
      voiceURI: voice.voiceURI || `${voice.name || 'static'}-${idx}`,
    }));
    synth.getVoices = function getVoices() {
      return voices.slice();
    };
    Object.defineProperty(synth, 'onvoiceschanged', {
      configurable: true,
      enumerable: true,
      get() {
        return null;
      },
      set() {},
    });
    synth.__static_fp_speech_patched = true;
  }

  function applyEventTimingSpoof(targetWindow) {
    const scope = targetWindow || window;
    if (!scope.Event || scope.__static_fp_event_timing_patched) {
      return;
    }
    const descriptor = Object.getOwnPropertyDescriptor(scope.Event.prototype, 'timeStamp');
    if (!descriptor || (!descriptor.configurable && !descriptor.writable)) {
      return;
    }
    const originalGetter = descriptor.get;
    const originalValue = descriptor.value;
    const rng = rngFactory(scopedSeed('event-timing', scope.location ? scope.location.href : 'window'));
    const lastPerType = new Map();

    const jitterConstructors = ['UIEvent', 'MouseEvent', 'PointerEvent', 'WheelEvent', 'KeyboardEvent', 'FocusEvent', 'TouchEvent']
      .map((name) => scope[name])
      .filter((ctor) => typeof ctor === 'function');

    const excludedConstructors = ['MessageEvent', 'CustomEvent']
      .map((name) => scope[name])
      .filter((ctor) => typeof ctor === 'function');

    function shouldJitter(evt) {
      if (!evt || typeof evt !== 'object') {
        return false;
      }
      if (excludedConstructors.some((ctor) => ctor && evt instanceof ctor)) {
        return false;
      }
      return jitterConstructors.some((ctor) => ctor && evt instanceof ctor);
    }

    try {
      Object.defineProperty(scope.Event.prototype, 'timeStamp', {
        configurable: true,
        enumerable: descriptor.enumerable,
        get() {
          let base;
          if (typeof originalGetter === 'function') {
            base = Number(originalGetter.call(this));
          } else if (originalValue !== undefined) {
            base = Number(originalValue);
          } else {
            base = Date.now();
          }
          if (!shouldJitter(this)) {
            return base;
          }
          const typeKey = typeof this.type === 'string' && this.type ? this.type : 'ui-event';
          const previous = lastPerType.get(typeKey) || base;
          const jitter = (rng() - 0.5) * 0.6;
          const next = Math.max(previous + 0.02, base + jitter);
          lastPerType.set(typeKey, next);
          return next;
        },
      });
      scope.__static_fp_event_timing_patched = true;
    } catch (_) {
      /* ignored */
    }
  }

  /*
  function applyMathNoise(targetWindow) {
    const scope = targetWindow || window;
    if (!scope.Math || scope.__static_fp_math_noise_patched) {
      return;
    }
    scope.__static_fp_math_noise_patched = true;
    const magnitude = 1e-10;
    const rng = rngFactory(scopedSeed('math-noise', config.name || 'static-profile'));
    const targets = ['sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 'asinh', 'acosh', 'atanh', 'exp', 'expm1', 'log', 'log1p', 'log10', 'log2', 'sqrt', 'cbrt'];
    targets.forEach((fn) => {
      if (typeof scope.Math[fn] !== 'function') {
        return;
      }
      const original = scope.Math[fn];
      scope.Math[fn] = new Proxy(original, {
        apply(target, thisArg, args) {
          const result = Reflect.apply(target, thisArg, args);
          if (typeof result !== 'number' || !Number.isFinite(result)) {
            return result;
          }
          return result + ((rng() - 0.5) * magnitude);
        },
      });
    });
    if (typeof scope.Math.pow === 'function') {
      const originalPow = scope.Math.pow;
      scope.Math.pow = new Proxy(originalPow, {
        apply(target, thisArg, args) {
          const result = Reflect.apply(target, thisArg, args);
          if (typeof result !== 'number' || !Number.isFinite(result)) {
            return result;
          }
          return result + ((rng() - 0.5) * magnitude);
        },
      });
    }
  }
  */

  function applyWebGpuSpoof(targetWindow) {
    const scope = targetWindow || window;
    const nav = scope.navigator;
    if (!nav || !nav.gpu || typeof nav.gpu.requestAdapter !== 'function' || nav.gpu.__static_fp_request_adapter) {
      return;
    }
    nav.gpu.__static_fp_request_adapter = true;
    const originalRequestAdapter = nav.gpu.requestAdapter.bind(nav.gpu);
    const adapterSeed = hashFn(`${config.webgl_renderer || 'static'}:${sessionId}`);

    function snapshotAdapter(adapter) {
      const info = {
        vendor: config.webgl_vendor || (adapter && adapter.info && adapter.info.vendor) || 'Google Inc. (NVIDIA)',
        architecture: (adapter && adapter.info && adapter.info.architecture) || 'static',
        device: (adapter && adapter.info && adapter.info.device) || adapterSeed.slice(0, 12),
        description: config.webgl_renderer || (adapter && adapter.info && adapter.info.description) || 'STATIC Adapter',
      };
      const features = (() => {
        if (Array.isArray(config.webgpu_features)) {
          return config.webgpu_features.slice();
        }
        if (adapter && adapter.features && typeof adapter.features[Symbol.iterator] === 'function') {
          return Array.from(adapter.features);
        }
        return [];
      })();
      const limits = {};
      const sourceLimits = (adapter && adapter.limits && typeof adapter.limits === 'object') ? adapter.limits : config.webgpu_limits;
      if (sourceLimits && typeof sourceLimits === 'object') {
        Object.keys(sourceLimits).forEach((key) => {
          const value = sourceLimits[key];
          if (typeof value === 'number' || typeof value === 'bigint') {
            limits[key] = Number(value);
          }
        });
      }
      return Object.freeze({
        info: Object.freeze(info),
        features: Object.freeze(features),
        limits: Object.freeze(limits),
        isFallbackAdapter: Boolean(adapter && adapter.isFallbackAdapter),
      });
    }

    nav.gpu.requestAdapter = function patchedRequestAdapter(options) {
      try {
        const result = originalRequestAdapter.call(nav.gpu, options);
        if (result && typeof result.then === 'function') {
          return result.then((adapter) => snapshotAdapter(adapter));
        }
        return Promise.resolve(snapshotAdapter(result));
      } catch (_) {
        return Promise.resolve(snapshotAdapter(null));
      }
    };
  }


  function applyAutomationEvasion(targetWindow) {
    if (config.enable_automation_evasion === false) {
      return;
    }

    const scope = targetWindow || window;
    const doc = scope.document;

    try {
      if (debug && scope === window) {
        console.info('[STATIC-FP] enabling automation evasion surface');
      }

      const automationProps = [
        '__webdriver_evaluate',
        '__driver_evaluate',
        '__selenium_evaluate',
        '__webdriver_script_fn',
        '__webdriver_script_function',
        '__fxdriver_evaluate',
        '__driver_unwrapped',
        '__webdriver_unwrapped',
        '__selenium_unwrapped',
        '__fxdriver_unwrapped',
        '__nightmare',
        'callPhantom',
        '_phantom',
        '_selenium',
        'selenium',
        '__selenium',
        '__webdriver',
        'domAutomation',
        'domAutomationController',
        '$cdc_asdjflasutopfhvcZLmcfl_',
        '$chrome_asyncScriptInfo',
        '__$webdriverAsyncExecutor',
        'webdriver',
      ];

      const disableDescriptor = {
        configurable: false,
        enumerable: false,
        get() {
          return undefined;
        },
        set() {
          return undefined;
        },
      };

      automationProps.forEach((prop) => {
        try {
          if (prop in scope) {
            delete scope[prop];
          }
          Object.defineProperty(scope, prop, disableDescriptor);
        } catch (_) {
          /* ignored */
        }
      });

      if (doc) {
        const docAutomationProps = ['webdriver', '__webdriver_evaluate', '__driver_evaluate'];
        docAutomationProps.forEach((prop) => {
          try {
            if (prop in doc) {
              delete doc[prop];
            }
            Object.defineProperty(doc, prop, {
              configurable: false,
              enumerable: false,
              get: () => undefined,
            });
          } catch (_) {
            /* ignored */
          }
        });

        if (typeof doc.hasFocus === 'function') {
          const originalHasFocus = doc.hasFocus;
          doc.hasFocus = function patchedHasFocus() {
            return true;
          };
          doc.hasFocus.toString = function patchedToString() {
            return originalHasFocus.toString();
          };
        }

        const safeDefineDocument = (prop, getter) => {
          try {
            Object.defineProperty(doc, prop, {
              configurable: true,
              enumerable: true,
              get: getter,
            });
          } catch (_) {
            /* ignored */
          }
        };

        safeDefineDocument('visibilityState', () => 'visible');
        safeDefineDocument('hidden', () => false);
      }

      const browserType = config.browser_type || config.browserType || 'chrome';
      const isChromium = browserType === 'chrome' || browserType === 'edge';
      const isFirefox = browserType === 'firefox';

      if (isChromium && !scope.chrome) {
        scope.chrome = {
          runtime: {
            OnInstalledReason: {
              CHROME_UPDATE: 'chrome_update',
              INSTALL: 'install',
              SHARED_MODULE_UPDATE: 'shared_module_update',
              UPDATE: 'update',
            },
            OnRestartRequiredReason: {
              APP_UPDATE: 'app_update',
              OS_UPDATE: 'os_update',
              PERIODIC: 'periodic',
            },
            PlatformArch: {
              ARM: 'arm',
              MIPS: 'mips',
              MIPS64: 'mips64',
              X86_32: 'x86-32',
              X86_64: 'x86-64',
            },
            PlatformNaclArch: {
              ARM: 'arm',
              MIPS: 'mips',
              MIPS64: 'mips64',
              X86_32: 'x86-32',
              X86_64: 'x86-64',
            },
            PlatformOs: {
              ANDROID: 'android',
              CROS: 'cros',
              LINUX: 'linux',
              MAC: 'mac',
              OPENBSD: 'openbsd',
              WIN: 'win',
            },
            RequestUpdateCheckStatus: {
              NO_UPDATE: 'no_update',
              THROTTLED: 'throttled',
              UPDATE_AVAILABLE: 'update_available',
            },
          },
          csi() {},
          loadTimes() {},
        };
      }

      if (isFirefox && scope.chrome) {
        try {
          delete scope.chrome;
          Object.defineProperty(scope, 'chrome', {
            configurable: false,
            enumerable: false,
            get: () => undefined,
          });
        } catch (_) {
          /* ignored */
        }
      }

      const nav = scope.navigator;
      if (nav) {
        try {
          delete nav.webdriver;
        } catch (_) {
          /* ignored */
        }
        try {
          Object.defineProperty(nav, 'webdriver', {
            configurable: true,
            enumerable: true,
            get() {
              return false;
            },
          });
        } catch (_) {
          /* ignored */
        }
      }
    } catch (err) {
      if (debug && scope === window) {
        console.error('[STATIC-FP] automation evasion error', err);
      }
    }
  }

  function applyGeolocationSpoof(targetWindow) {
    const scope = targetWindow || window;
    const nav = scope.navigator;
    const geoEnabled = config.enable_geolocation_spoof !== false && config.enable_automation_evasion !== false;
    if (!geoEnabled || !nav || !nav.geolocation) {
      return;
    }

    try {
      const deny = (error) => {
        if (typeof error === 'function') {
          error({
            code: 1,
            message: 'User denied Geolocation',
            PERMISSION_DENIED: 1,
            POSITION_UNAVAILABLE: 2,
            TIMEOUT: 3,
          });
        }
      };

      nav.geolocation.getCurrentPosition = function spoofedGetCurrentPosition(success, error) {
        deny(error);
      };

      nav.geolocation.watchPosition = function spoofedWatchPosition(success, error) {
        deny(error);
        return Math.floor(Math.random() * 10000);
      };

      nav.geolocation.clearWatch = function noopClearWatch() {};

      if (debug) {
        console.info('[STATIC-FP] geolocation access disabled (automation evasion)');
      }
    } catch (err) {
      if (debug) {
        console.error('[STATIC-FP] geolocation spoof error', err);
      }
    }
  }

  // Mirrors the spoofing surface into every same-origin iframe so nested browsing
  // contexts inherit the same canvas/audio/webgl fingerprints as the top document.
  function setupIframePropagation() {
    if (config.enable_iframe_protection === false) {
      return;
    }

    const FRAME_MARK = '__static_iframe_spoof_ready';

    function bindIframe(iframe) {
      if (!iframe || iframe.__static_fp_iframe_bound) {
        return;
      }
      iframe.__static_fp_iframe_bound = true;

      const attemptPatch = () => {
        try {
          if (iframe.contentWindow) {
            patchWindow(iframe.contentWindow);
          }
        } catch (_) {
          /* ignored */
        }
      };

      iframe.addEventListener('load', attemptPatch);
      attemptPatch();
    }

    function patchWindow(targetWindow) {
      if (!targetWindow || targetWindow === window || targetWindow[FRAME_MARK]) {
        return;
      }
      try {
        if (targetWindow.location && typeof targetWindow.location.href === 'string') {
          void targetWindow.location.href;
        }
      } catch (_) {
        return;
      }

      try {
        if (!targetWindow.__STATIC_CONFIG__ && window.__STATIC_CONFIG__) {
          targetWindow.__STATIC_CONFIG__ = window.__STATIC_CONFIG__;
        }
        targetWindow.__STATIC_SESSION_ID = window.__STATIC_SESSION_ID;
        targetWindow.__404_session_id = window.__404_session_id;
        if (typeof window.__static_hash === 'function') {
          targetWindow.__static_hash = window.__static_hash;
        }
        if (typeof window.__static_rng === 'function') {
          targetWindow.__static_rng = window.__static_rng;
        }
        if (window.__static_canvas_strategy) {
          targetWindow.__static_canvas_strategy = cloneCanvasStrategy(window.__static_canvas_strategy);
        }
        if (window.__static_canvas_plan_executor && !targetWindow.__static_canvas_plan_executor) {
          targetWindow.__static_canvas_plan_executor = window.__static_canvas_plan_executor;
        }
      } catch (_) {
        /* ignored */
      }

      copyPrototypeMethods(window.HTMLCanvasElement, targetWindow.HTMLCanvasElement, ['toDataURL', 'toBlob', 'getContext']);
      copyPrototypeMethods(window.CanvasRenderingContext2D, targetWindow.CanvasRenderingContext2D, ['getImageData']);
      copyPrototypeMethods(window.OfflineAudioContext, targetWindow.OfflineAudioContext, ['startRendering']);
      copyPrototypeMethods(window.webkitOfflineAudioContext, targetWindow.webkitOfflineAudioContext, ['startRendering']);
      copyPrototypeMethods(window.BaseAudioContext, targetWindow.BaseAudioContext, ['createOscillator']);
      copyPrototypeMethods(window.AudioContext, targetWindow.AudioContext, ['createOscillator']);
      copyPrototypeMethods(window.webkitAudioContext, targetWindow.webkitAudioContext, ['createOscillator']);

      applyDeviceSpoof(targetWindow);
      applyAutomationEvasion(targetWindow);
      applyGeolocationSpoof(targetWindow);
      applyCanvasSpoof(targetWindow);
      applyOffscreenCanvasSpoof(targetWindow);
      applyWebGLSpoof(targetWindow);
      applyAudioSpoof(targetWindow);
      applyExtendedAudioGraphSpoof(targetWindow);
      applyMediaDevicesSpoof(targetWindow);
      applyGamepadSpoof(targetWindow);
      applySpeechSynthesisSpoof(targetWindow);
      applyWebRTCSpoof(targetWindow);
      applyWebGpuSpoof(targetWindow);
      applyEventTimingSpoof(targetWindow);

      targetWindow.__static_advanced_protections_active = true;
      targetWindow.__404_advanced_protections_active = true;
      targetWindow.__static_advanced_protections_version = window.__static_advanced_protections_version;
      targetWindow.__404_advanced_protections_version = window.__static_advanced_protections_version;
      targetWindow[FRAME_MARK] = true;

      try {
        const doc = targetWindow.document;
        if (doc && typeof doc.querySelectorAll === 'function') {
          doc.querySelectorAll('iframe').forEach((nested) => bindIframe(nested));
        }
      } catch (_) {
        /* ignored */
      }
    }

    function scanForIframes(root) {
      if (!root || typeof root.querySelectorAll !== 'function') {
        return;
      }
      try {
        root.querySelectorAll('iframe').forEach((iframe) => bindIframe(iframe));
      } catch (_) {
        /* ignored */
      }
    }

    scanForIframes(document);

    if (window.MutationObserver) {
      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.type !== 'childList' || !mutation.addedNodes) {
            continue;
          }
          mutation.addedNodes.forEach((node) => {
            if (!node) {
              return;
            }
            if (node.tagName === 'IFRAME') {
              bindIframe(node);
            } else if (typeof node.querySelectorAll === 'function') {
              node.querySelectorAll('iframe').forEach((iframe) => bindIframe(iframe));
            }
          });
        }
      });
      observer.observe(document.documentElement || document.body, { childList: true, subtree: true });
    }
  }

  // Copies patched prototype methods (canvas/audio/webgl) from the parent window
  // into a target iframe without re-running the heavy setup logic per context.
  function copyPrototypeMethods(sourceCtor, targetCtor, methods) {
    if (!sourceCtor || !targetCtor || !sourceCtor.prototype || !targetCtor.prototype) {
      return;
    }
    methods.forEach((method) => {
      if (!method) {
        return;
      }
      const descriptor = Object.getOwnPropertyDescriptor(sourceCtor.prototype, method);
      if (!descriptor) {
        return;
      }
      try {
        Object.defineProperty(targetCtor.prototype, method, descriptor);
      } catch (_) {
        try {
          targetCtor.prototype[method] = sourceCtor.prototype[method];
        } catch (_) {
          /* ignored */
        }
      }
    });
  }

  function defineNavigatorOverride(targets, key, value) {
    if (value === undefined) {
      return;
    }
    for (let i = 0; i < targets.length; i += 1) {
      const descriptor = {
        configurable: true,
        enumerable: true,
        get() {
          return value;
        },
      };
      try {
        Object.defineProperty(targets[i], key, descriptor);
        return;
      } catch (_) {
        /* ignored */
      }
    }
  }

  function removeNavigatorProperty(targets, key) {
    for (let i = 0; i < targets.length; i += 1) {
      try {
        delete targets[i][key];
      } catch (_) {
        /* ignored */
      }
    }
  }

  function resolveVendorValue(browserType) {
    if (Object.prototype.hasOwnProperty.call(config, 'vendor')) {
      return config.vendor;
    }
    return browserType === 'firefox' ? '' : 'Google Inc.';
  }

  function resolveVendorFlavors(browserType) {
    if (Object.prototype.hasOwnProperty.call(config, 'vendor_flavors')) {
      if (config.vendor_flavors === null) {
        return null;
      }
      if (Array.isArray(config.vendor_flavors)) {
        return Object.freeze(config.vendor_flavors.slice());
      }
      return Object.freeze([]);
    }
    if (browserType === 'firefox') {
      return null;
    }
    return Object.freeze(['chrome']);
  }

  function buildWebGLParameterMap(gl, profile) {
    const defaults = [
      ['MAX_TEXTURE_SIZE', 16384],
      ['MAX_RENDERBUFFER_SIZE', 16384],
      ['MAX_CUBE_MAP_TEXTURE_SIZE', 16384],
      ['MAX_VERTEX_UNIFORM_VECTORS', 4096],
      ['MAX_FRAGMENT_UNIFORM_VECTORS', 4096],
      ['MAX_VARYING_VECTORS', 30],
      ['MAX_VERTEX_ATTRIBS', 16],
      ['MAX_TEXTURE_IMAGE_UNITS', 16],
      ['MAX_VERTEX_TEXTURE_IMAGE_UNITS', 16],
      ['MAX_COMBINED_TEXTURE_IMAGE_UNITS', 32],
      ['MAX_SAMPLES', 4],
      ['MAX_DRAW_BUFFERS_WEBGL', 4],
      ['MAX_VIEWPORT_DIMS', [32767, 32767]],
      ['ALIASED_POINT_SIZE_RANGE', [1, 64]],
      ['ALIASED_LINE_WIDTH_RANGE', [1, 8]],
      ['RED_BITS', 8],
      ['GREEN_BITS', 8],
      ['BLUE_BITS', 8],
      ['ALPHA_BITS', 8],
      ['DEPTH_BITS', 24],
      ['STENCIL_BITS', 8],
    ];

    const map = new Map();
    defaults.forEach(([name, value]) => storeParamOverride(map, gl, name, value));

    const custom = profile.webgl_parameters || profile.webgl_params;
    if (custom && typeof custom === 'object') {
      Object.entries(custom).forEach(([name, value]) => {
        storeParamOverride(map, gl, name, value);
      });
    }

    return map;
  }

  function storeParamOverride(map, gl, identifier, rawValue) {
    const enumValue = lookupGLEnum(gl, identifier);
    if (enumValue === null) {
      return;
    }
    const resolvedName = typeof identifier === 'string'
      ? identifier.toUpperCase()
      : resolveEnumName(gl, enumValue) || String(identifier);
    map.set(enumValue, { name: resolvedName, value: rawValue });
  }

  function lookupGLEnum(gl, identifier) {
    if (typeof identifier === 'number' && Number.isFinite(identifier)) {
      return identifier;
    }
    if (typeof identifier === 'string') {
      const trimmed = identifier.trim();
      if (/^0x/i.test(trimmed)) {
        const parsed = parseInt(trimmed, 16);
        return Number.isNaN(parsed) ? null : parsed;
      }
      const upper = trimmed.toUpperCase();
      const tables = [gl, window.WebGLRenderingContext, window.WebGL2RenderingContext];
      for (let i = 0; i < tables.length; i += 1) {
        const table = tables[i];
        if (table && typeof table[upper] === 'number') {
          return table[upper];
        }
      }
    }
    return null;
  }

  function resolveEnumName(gl, value) {
    const tables = [window.WebGLRenderingContext, window.WebGL2RenderingContext, gl];
    for (let i = 0; i < tables.length; i += 1) {
      const table = tables[i];
      if (!table) {
        continue;
      }
      for (const key in table) {
        if (typeof table[key] === 'number' && table[key] === value) {
          return key;
        }
      }
    }
    return null;
  }

  function materializeParamValue(entry) {
    const name = entry.name || '';
    if (name === 'ALIASED_POINT_SIZE_RANGE' || name === 'ALIASED_LINE_WIDTH_RANGE') {
      return new Float32Array(normalizePair(entry.value));
    }
    if (name === 'MAX_VIEWPORT_DIMS') {
      return new Int32Array(normalizePair(entry.value));
    }
    if (ArrayBuffer.isView(entry.value)) {
      return entry.value.slice ? entry.value.slice() : new entry.value.constructor(entry.value);
    }
    if (Array.isArray(entry.value)) {
      return entry.value.slice();
    }
    return entry.value;
  }

  function normalizePair(value) {
    const list = toClonedArray(value);
    if (list.length === 1) {
      list.push(list[0]);
    }
    if (list.length === 0) {
      return [0, 0];
    }
    const first = Number(list[0]) || 0;
    const second = Number(list[1] !== undefined ? list[1] : list[0]) || 0;
    return [first, second];
  }

  function toClonedArray(value) {
    if (Array.isArray(value)) {
      return value.slice();
    }
    if (ArrayBuffer.isView(value)) {
      return Array.prototype.slice.call(value);
    }
    if (value === undefined) {
      return [];
    }
    return [value];
  }

  function buildSessionCanvasKey(canvasHash, id, driftEnabled) {
    const base = canvasHash || 'static_canvas';
    return driftEnabled ? `${base}_${id}` : `${base}_static`;
  }

  function generateMD5StyleHash(str) {
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;

    for (let i = 0; i < str.length; i += 1) {
      const k = str.charCodeAt(i);
      h0 = (h0 + k) | 0;
      h1 = (h1 ^ k) | 0;
      h2 = (h2 + (k << 8)) | 0;
      h3 = (h3 ^ (k << 16)) | 0;

      h0 = (((h0 << 13) | (h0 >>> 19)) + h1) | 0;
      h1 = (((h1 << 17) | (h1 >>> 15)) + h2) | 0;
      h2 = (((h2 << 5) | (h2 >>> 27)) + h3) | 0;
      h3 = (((h3 << 11) | (h3 >>> 21)) + h0) | 0;
    }

    const hex = (n) => (`00000000${(n >>> 0).toString(16)}`).slice(-8);
    return hex(h0) + hex(h1) + hex(h2) + hex(h3);
  }

  function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i += 1) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return hash;
  }

  function normalizeCanvasNoise(raw) {
    const cfg = (raw && typeof raw === 'object') ? raw : {};
    const toNumber = (value, fallback) => (typeof value === 'number' && Number.isFinite(value) ? value : fallback);
    const toBool = (value, fallback) => (typeof value === 'boolean' ? value : fallback);
    const pickMode = (value, fallback) => (value === 'per_call' ? 'per_call' : (value === 'session' ? 'session' : fallback));

    const stratSource = (cfg.strategy && typeof cfg.strategy === 'object') ? cfg.strategy : null;
    const stratEphemeral = stratSource && typeof stratSource.ephemeral === 'object' ? stratSource.ephemeral : null;

    const deltaMin = toNumber((stratSource && stratSource.delta_min) ?? cfg.delta_min, 1);
    const deltaMax = toNumber((stratSource && stratSource.delta_max) ?? cfg.delta_max ?? cfg.delta_min, Math.max(deltaMin + 1, 2));
    const defaultStride = Math.max(3, toNumber((stratSource && stratSource.stride) ?? cfg.default_stride ?? cfg.stride, 10));
    const smallDeltaMin = toNumber(cfg.small_canvas_delta_min, Math.max(1, deltaMin));
    const smallDeltaMax = toNumber(cfg.small_canvas_delta_max ?? cfg.small_canvas_delta_min, Math.max(smallDeltaMin + 1, deltaMax));

    const strategy = {
      mode: pickMode((stratSource && stratSource.mode) ?? cfg.mode, 'session'),
      stride: Math.max(3, toNumber((stratSource && stratSource.stride) ?? cfg.stride, defaultStride)),
      delta_min: deltaMin,
      delta_max: Math.max(deltaMin, deltaMax),
      alpha: toBool((stratSource && stratSource.alpha) ?? cfg.alpha ?? true, true),
      context_aware: toBool((stratSource && stratSource.context_aware) ?? cfg.context_aware, true),
      ephemeral: {
        enabled: toBool((stratEphemeral && stratEphemeral.enabled) ?? cfg.ephemeral_enabled ?? true, true),
        scale: Math.max(0.1, toNumber((stratEphemeral && stratEphemeral.scale) ?? cfg.ephemeral_scale, 1.5)),
      },
    };

    const smallSurfaceStrategy = {
      mode: pickMode(cfg.small_canvas_mode, 'per_call'),
      stride: Math.max(3, toNumber(cfg.small_canvas_stride_override ?? cfg.small_canvas_stride, Math.max(5, strategy.stride >> 1))),
      delta_min: smallDeltaMin,
      delta_max: Math.max(smallDeltaMax, smallDeltaMin),
    };

    return {
      small_canvas_threshold: toNumber(cfg.small_canvas_threshold, 16),
      small_canvas_stride: toNumber(cfg.small_canvas_stride, Math.max(20, defaultStride)),
      default_stride: defaultStride,
      noise_probability: toNumber(cfg.noise_probability, 0.1),
      delta_min: deltaMin,
      delta_max: Math.max(deltaMin, deltaMax),
      integer_delta: toBool(cfg.integer_delta, true),
      touch_alpha: toBool(cfg.touch_alpha, false),
      log_activity: toBool(cfg.log_activity, false),
      strategy,
      small_surface_strategy: smallSurfaceStrategy,
    };
  }

  function cloneCanvasStrategy(strategy) {
    if (!strategy || typeof strategy !== 'object') {
      return null;
    }
    const stride = Math.max(3, Number(strategy.stride) || 17);
    const deltaMin = Number(strategy.delta_min);
    const resolvedDeltaMin = Number.isFinite(deltaMin) ? Math.max(1, deltaMin) : 1;
    const deltaMaxRaw = Number(strategy.delta_max);
    const resolvedDeltaMax = Number.isFinite(deltaMaxRaw)
      ? Math.max(resolvedDeltaMin, deltaMaxRaw)
      : Math.max(resolvedDeltaMin + 1, 3);
    const ephemeral = strategy.ephemeral && typeof strategy.ephemeral === 'object'
      ? strategy.ephemeral
      : { enabled: true, scale: 1.5 };

    return {
      mode: strategy.mode === 'per_call' ? 'per_call' : 'session',
      stride,
      delta_min: resolvedDeltaMin,
      delta_max: resolvedDeltaMax,
      alpha: strategy.alpha !== false,
      context_aware: strategy.context_aware !== false,
      ephemeral: {
        enabled: ephemeral.enabled !== false,
        scale: Math.max(0.1, Number(ephemeral.scale) || 1.5),
      },
    };
  }
})();
