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

(function applyAdvancedFingerprintProtections() {

    'use strict';

    if (window.__404_advanced_protections_active) {
        console.warn('[404] Protections already applied');
        return;
    }

    if (!window.__404_bootstrap_active) {
        console.error('[404] Bootstrap missing - partial protection only');
    }

    if (!window.__404_shim_active) {
        console.warn('[404] Globals shim missing - partial protection only');
    }

  if (!window.__404_config_ready) {
    console.error('[404] Config not loaded - aborting protections');
    return; 
  }

  function getConfig() {
    return window.__fpConfig || {};
  }

  function createPRNG(seed) {
    const config = getConfig();
    const fullSeed = (config.name || 'default') + (seed || 'default_seed');

    let state = 0;
    for (let i = 0; i < fullSeed.length; i++) {
      state = ((state << 5) - state) + fullSeed.charCodeAt(i);
      state = state & state;
    }
    state = state >>> 0 || 1;

    return function() {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) / 0x100000000;
    };
  }

  const config = getConfig();
  const debug = config.debug || false;

  const enableDrift = config.enable_fingerprint_drift !== false; 

  if (enableDrift && !window.__404_session_id) {

    const timestamp = Date.now();
    const random = Math.random();
    const perfNow = performance.now();
    const entropy = timestamp.toString(36) + random.toString(36).substr(2, 9) + perfNow.toString(36);

    let hash = 0;
    for (let i = 0; i < entropy.length; i++) {
      hash = ((hash << 5) - hash) + entropy.charCodeAt(i);
      hash = hash & hash;
    }
    window.__404_session_id = Math.abs(hash).toString(36);

    if (debug) console.log('[404-SPOOF] Session ID generated:', window.__404_session_id);
  } else if (!enableDrift) {

    window.__404_session_id = 'static';
    if (debug) console.log('[404-SPOOF] Fingerprint drift disabled (static mode)');
  }

  function generateMD5StyleHash(str) {
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;

    for (let i = 0; i < str.length; i++) {
      const k = str.charCodeAt(i);
      h0 = (h0 + k) | 0;
      h1 = (h1 ^ k) | 0;
      h2 = (h2 + (k << 8)) | 0;
      h3 = (h3 ^ (k << 16)) | 0;

      h0 = ((h0 << 13) | (h0 >>> 19)) + h1 | 0;
      h1 = ((h1 << 17) | (h1 >>> 15)) + h2 | 0;
      h2 = ((h2 << 5) | (h2 >>> 27)) + h3 | 0;
      h3 = ((h3 << 11) | (h3 >>> 21)) + h0 | 0;
    }

    const hex = (n) => {
      return ('00000000' + (n >>> 0).toString(16)).slice(-8);
    };

    return hex(h0) + hex(h1) + hex(h2) + hex(h3);
  }

  const sessionCanvasHash = config.canvas_hash + (enableDrift ? '_' + window.__404_session_id : '');
  const sessionAudioHash = config.audio_hash + (enableDrift ? '_' + window.__404_session_id : '');

  const audioRng = createPRNG(sessionAudioHash || 'default_audio');

  const displayCanvasHash = generateMD5StyleHash(sessionCanvasHash);

  if (config.enable_math_noise !== false) {
    try {
      const mathNoisePRNG = createPRNG('math_noise_' + window.__404_session_id);
      
      const nativeMath = {
        tan: Math.tan,
        sin: Math.sin,
        cos: Math.cos,
        asin: Math.asin,
        acos: Math.acos,
        atan: Math.atan,
        sinh: Math.sinh,
        cosh: Math.cosh,
        tanh: Math.tanh,
        asinh: Math.asinh,
        acosh: Math.acosh,
        atanh: Math.atanh,
        exp: Math.exp,
        expm1: Math.expm1,
        log: Math.log,
        log1p: Math.log1p,
        log10: Math.log10,
        log2: Math.log2,
        pow: Math.pow,
        sqrt: Math.sqrt,
        cbrt: Math.cbrt
      };
      
      // Apply noise to trigonometric and transcendental functions
      const noiseMagnitude = 1e-10; 
      
      ['tan', 'sin', 'cos', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 
       'asinh', 'acosh', 'atanh', 'exp', 'expm1', 'log', 'log1p', 'log10', 
       'log2', 'sqrt', 'cbrt'].forEach(fn => {
        Math[fn] = new Proxy(nativeMath[fn], {
          apply: function(target, thisArg, args) {
            const result = Reflect.apply(target, thisArg, args);
            if (typeof result !== 'number' || !isFinite(result)) return result;
            
            // Add deterministic noise based on input and session
            const noise = (mathNoisePRNG() - 0.5) * noiseMagnitude;
            return result + noise;
          }
        });
      });
      
      // Special handling for pow (two arguments)
      Math.pow = new Proxy(nativeMath.pow, {
        apply: function(target, thisArg, args) {
          const result = Reflect.apply(target, thisArg, args);
          if (typeof result !== 'number' || !isFinite(result)) return result;
          
          const noise = (mathNoisePRNG() - 0.5) * noiseMagnitude;
          return result + noise;
        }
      });
      
      if (debug) console.log('[404-SPOOF] ✓ Math API noise injection active (magnitude: 1e-10)');
    } catch (e) {
      console.error('[404-SPOOF] Math noise injection error:', e);
    }
  }

  if (debug) {
    console.log('[404-SPOOF] Canvas hash (display):', displayCanvasHash);
    console.log('[404-SPOOF] Canvas hash (internal):', sessionCanvasHash);
    console.log('[404-SPOOF] Fingerprint drift:', enableDrift ? 'enabled' : 'disabled');
  }

  function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  function applyCanvasNoise(imageData) {
    if (!imageData || !imageData.data) return;

    const data = imageData.data;
    const len = data.length;

    const canvasSignature = sessionCanvasHash + imageData.width + 'x' + imageData.height;
    const seed = hashString(canvasSignature);

    let state = seed;
    function noise() {
      state |= 0;
      state = state + 0x6D2B79F5 | 0;
      let t = Math.imul(state ^ state >>> 15, 1 | state);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    }

    const interval = imageData.width <= 16 && imageData.height <= 16 ? 20 : 10;

    let pixelsModified = 0;
    for (let i = 0; i < len; i += interval) {

      if (noise() < 0.1) {

        const noiseVal = noise() > 0.5 ? 1 : -1;

        if (i < len) data[i] = Math.max(0, Math.min(255, data[i] + noiseVal));
        if (i + 1 < len) data[i + 1] = Math.max(0, Math.min(255, data[i + 1] + noiseVal));
        if (i + 2 < len) data[i + 2] = Math.max(0, Math.min(255, data[i + 2] + noiseVal));
        pixelsModified++;
      }
    }

    if (debug) console.log('[404-SPOOF] Canvas noise applied:', pixelsModified, 'pixels modified');
  }

  if (config.enable_canvas_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying canvas protection...');

      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const originalToBlob = HTMLCanvasElement.prototype.toBlob;
      const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

      CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
        const imageData = originalGetImageData.call(this, sx, sy, sw, sh);

        applyCanvasNoise(imageData);

        if (debug) console.log('[404-SPOOF] Canvas getImageData intercepted:', imageData.width + 'x' + imageData.height);

        return imageData;
      };

      HTMLCanvasElement.prototype.toDataURL = function() {
        try {
          const ctx = this.getContext('2d');
          if (ctx && this.width > 0 && this.height > 0) {

            const imageData = originalGetImageData.call(ctx, 0, 0, this.width, this.height);

            const backup = new Uint8ClampedArray(imageData.data);

            applyCanvasNoise(imageData);

            ctx.putImageData(imageData, 0, 0);

            const result = originalToDataURL.apply(this, arguments);

            imageData.data.set(backup);
            ctx.putImageData(imageData, 0, 0);

            return result;
          }
        } catch (e) {
          if (debug) console.warn('[404-SPOOF] Canvas toDataURL error:', e);
        }
        return originalToDataURL.apply(this, arguments);
      };

      HTMLCanvasElement.prototype.toBlob = function(callback) {
        try {
          const ctx = this.getContext('2d');
          if (ctx && this.width > 0 && this.height > 0) {

            const imageData = originalGetImageData.call(ctx, 0, 0, this.width, this.height);

            const backup = new Uint8ClampedArray(imageData.data);

            applyCanvasNoise(imageData);

            ctx.putImageData(imageData, 0, 0);

            const wrappedCallback = function(blob) {

              imageData.data.set(backup);
              ctx.putImageData(imageData, 0, 0);

              if (callback) callback(blob);
            };

            return originalToBlob.call(this, wrappedCallback, ...Array.from(arguments).slice(1));
          }
        } catch (e) {
          if (debug) console.warn('[404-SPOOF] Canvas toBlob error:', e);
        }
        return originalToBlob.apply(this, arguments);
      };

      if (debug) console.log('[404-SPOOF] ✓ Canvas protection applied');

    } catch (e) {
      console.error('[404-SPOOF] Canvas protection error:', e);
    }
  }

  if (config.enable_webgl_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying WebGL protection...');

      const originalGetContext = HTMLCanvasElement.prototype.getContext;

      HTMLCanvasElement.prototype.getContext = function(contextType, options) {
        const context = originalGetContext.call(this, contextType, options);

        if (context && (contextType === 'webgl' || contextType === 'webgl2' || contextType === 'experimental-webgl')) {
          const originalGetParameter = context.getParameter;

          context.getParameter = function(pname) {
            switch (pname) {
              case context.VENDOR:
                return config.webgl_vendor || 'Google Inc. (NVIDIA)';
              case context.RENDERER:
                return config.webgl_renderer || 'ANGLE (NVIDIA)';
              case context.VERSION:
                return contextType === 'webgl2' ? 'WebGL 2.0' : 'WebGL 1.0';
              case context.SHADING_LANGUAGE_VERSION:
                return contextType === 'webgl2' ? 'WebGL GLSL ES 3.00' : 'WebGL GLSL ES 1.0';
              case context.MAX_TEXTURE_SIZE:
                return 16384;
              case context.MAX_VIEWPORT_DIMS:
                return new Int32Array([16384, 16384]);
              case context.MAX_VERTEX_ATTRIBS:
                return 16;
              case context.MAX_FRAGMENT_UNIFORM_VECTORS:
                return 1024;
              case context.MAX_VERTEX_UNIFORM_VECTORS:
                return 1024;
              case context.ALIASED_POINT_SIZE_RANGE:
                return new Float32Array([1, 255]);
              case context.ALIASED_LINE_WIDTH_RANGE:
                return new Float32Array([1, 10]);
              default:
                return originalGetParameter.call(this, pname);
            }
          };

          const originalGetExtension = context.getExtension;
          context.getExtension = function(name) {
            const allowed = [
              'OES_texture_float',
              'OES_texture_half_float',
              'WEBGL_lose_context',
              'WEBGL_depth_texture'
            ];

            if (name.includes('debug') || name.includes('WEBGL_debug')) {
              return null;
            }

            if (allowed.includes(name)) {
              return originalGetExtension.call(this, name);
            }

            return null;
          };

          const originalGetSupportedExtensions = context.getSupportedExtensions;
          context.getSupportedExtensions = function() {
            return [
              'OES_texture_float',
              'OES_texture_half_float',
              'WEBGL_lose_context',
              'WEBGL_depth_texture'
            ];
          };
        }

        return context;
      };

      if (debug) console.log('[404-SPOOF] ✓ WebGL protection applied');

    } catch (e) {
      console.error('[404-SPOOF] WebGL protection error:', e);
    }
  }

  if (config.enable_audio_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying audio protection...');

      const OriginalOfflineAudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;

      if (OriginalOfflineAudioContext && OriginalOfflineAudioContext.prototype.startRendering) {
        const originalStartRendering = OriginalOfflineAudioContext.prototype.startRendering;

        OriginalOfflineAudioContext.prototype.startRendering = function() {
          return originalStartRendering.call(this).then(function(audioBuffer) {
            for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
              const channelData = audioBuffer.getChannelData(channel);
              for (let i = 0; i < channelData.length; i++) {
                const noise = (audioRng() - 0.5) * 0.0001;
                channelData[i] = channelData[i] + noise;
              }
            }
            return audioBuffer;
          });
        };
      }
      
      // Hook createOscillator to add frequency jitter
      // This changes the base audio fingerprint (35.749972... -> 35.749xxx...)
      const BaseAudioContext = window.BaseAudioContext || window.AudioContext || window.webkitAudioContext;
      if (BaseAudioContext && BaseAudioContext.prototype.createOscillator) {
        const originalCreateOscillator = BaseAudioContext.prototype.createOscillator;
        
        BaseAudioContext.prototype.createOscillator = function() {
          const oscillator = originalCreateOscillator.call(this);
          const originalFrequencyGetter = Object.getOwnPropertyDescriptor(
            Object.getPrototypeOf(oscillator.frequency),
            'value'
          ).get;
          
          // Add tiny frequency offset (±0.00001 Hz - imperceptible)
          const freqJitter = (audioRng() - 0.5) * 0.00002;
          
          // Intercept frequency.value setter
          const originalSetter = Object.getOwnPropertyDescriptor(
            Object.getPrototypeOf(oscillator.frequency),
            'value'
          ).set;
          
          Object.defineProperty(oscillator.frequency, 'value', {
            get: function() {
              const baseValue = originalFrequencyGetter.call(this);
              return baseValue + freqJitter;
            },
            set: function(v) {
              originalSetter.call(this, v);
            },
            configurable: true,
            enumerable: true
          });
          
          return oscillator;
        };
        
        if (debug) console.log('[404-SPOOF] ✓ Audio oscillator frequency jitter enabled');
      }

      if (debug) console.log('[404-SPOOF] ✓ Audio protection applied');

    } catch (e) {
      console.error('[404-SPOOF] Audio protection error:', e);
    }
  }

  if (config.enable_timezone_spoof && config.timezone) {
    try {
      if (debug) console.log('[404-SPOOF] Applying timezone spoofing...');

      function calculateOffset(date, timezone) {
        if (timezone === 'America/New_York') {
          const month = date.getMonth();  

          if (month >= 2 && month <= 9) {
            return 240;  
          }
          return 300;  
        }

        return config.timezone_offset || 300;
      }

      const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
      Date.prototype.getTimezoneOffset = function() {
        return calculateOffset(this, config.timezone);
      };

      const originalToString = Date.prototype.toString;
      Date.prototype.toString = function() {

        const actualOffset = originalGetTimezoneOffset.call(this);     
        const spoofedOffset = calculateOffset(this, config.timezone);  
        const offsetDiff = actualOffset - spoofedOffset;               

        const adjustedTime = new Date(this.getTime() + (offsetDiff * 60000));
        const original = originalToString.call(adjustedTime);

        const isDST = spoofedOffset === 240;  
        let tzAbbr = 'EST';
        let tzOffset = '-0500';

        if (config.timezone === 'America/New_York') {
          tzAbbr = isDST ? 'EDT' : 'EST';
          tzOffset = isDST ? '-0400' : '-0500';
        }

        return original
          .replace(/GMT[+-]\d{4}/, 'GMT' + tzOffset)
          .replace(/\([^)]+\)/, `(${tzAbbr})`);
      };

      const originalToTimeString = Date.prototype.toTimeString;
      Date.prototype.toTimeString = function() {
        const actualOffset = originalGetTimezoneOffset.call(this);
        const spoofedOffset = calculateOffset(this, config.timezone);
        const offsetDiff = actualOffset - spoofedOffset;

        const adjustedTime = new Date(this.getTime() + (offsetDiff * 60000));
        const original = originalToTimeString.call(adjustedTime);

        const isDST = spoofedOffset === 240;
        let tzAbbr = 'EST';
        let tzOffset = '-0500';

        if (config.timezone === 'America/New_York') {
          tzAbbr = isDST ? 'EDT' : 'EST';
          tzOffset = isDST ? '-0400' : '-0500';
        }

        return original
          .replace(/GMT[+-]\d{4}/, 'GMT' + tzOffset)
          .replace(/\([^)]+\)/, `(${tzAbbr})`);
      };

      const originalToLocaleString = Date.prototype.toLocaleString;
      Date.prototype.toLocaleString = function(locales, options) {

        const newOptions = { ...options, timeZone: config.timezone };
        return originalToLocaleString.call(this, locales, newOptions);
      };

      if (window.Intl && window.Intl.DateTimeFormat) {
        const OriginalDateTimeFormat = window.Intl.DateTimeFormat;

        window.Intl.DateTimeFormat = function(locales, options) {

          const newOptions = { ...options, timeZone: config.timezone };
          return new OriginalDateTimeFormat(locales, newOptions);
        };

        Object.setPrototypeOf(window.Intl.DateTimeFormat, OriginalDateTimeFormat);
        window.Intl.DateTimeFormat.prototype = OriginalDateTimeFormat.prototype;

        if (window.Intl.DateTimeFormat.prototype.resolvedOptions) {
          const originalResolvedOptions = window.Intl.DateTimeFormat.prototype.resolvedOptions;
          window.Intl.DateTimeFormat.prototype.resolvedOptions = function() {
            const options = originalResolvedOptions.call(this);

            options.timeZone = config.timezone;
            return options;
          };
        }
      }

      if (debug) console.log('[404-SPOOF] ✓ Timezone spoofing applied');

    } catch (e) {
      console.error('[404-SPOOF] Timezone spoofing error:', e);
    }
  }

  if (config.enable_webrtc_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying WebRTC protection...');

      if (window.RTCPeerConnection) {
        const OriginalRTCPeerConnection = window.RTCPeerConnection;

        window.RTCPeerConnection = function(config_rtc) {
          if (config_rtc && config_rtc.iceServers) {
            config_rtc.iceServers = [];
          }

          const pc = new OriginalRTCPeerConnection(config_rtc);

          const originalAddEventListener = pc.addEventListener.bind(pc);
          const originalRemoveEventListener = pc.removeEventListener.bind(pc);
          let iceCandidateHandlers = [];

          pc.addEventListener = function(type, handler, ...args) {
            if (type === 'icecandidate') {
              const wrappedHandler = function(event) {
                if (event.candidate && event.candidate.candidate) {
                  const candidateStr = event.candidate.candidate;
                  
                  if (candidateStr.includes('typ host') || candidateStr.includes('typ srflx') || candidateStr.includes('typ relay')) {
                    if (debug) console.log('[404-SPOOF] Blocked WebRTC candidate:', candidateStr.substring(0, 50) + '...');
                    return;
                  }
                }
                
                if (event.candidate === null) {
                  handler.call(this, event);
                }
              };
              
              iceCandidateHandlers.push({ original: handler, wrapped: wrappedHandler });
              return originalAddEventListener.call(this, type, wrappedHandler, ...args);
            }
            return originalAddEventListener.call(this, type, handler, ...args);
          };

          pc.removeEventListener = function(type, handler, ...args) {
            if (type === 'icecandidate') {
              const entry = iceCandidateHandlers.find(h => h.original === handler);
              if (entry) {
                iceCandidateHandlers = iceCandidateHandlers.filter(h => h !== entry);
                return originalRemoveEventListener.call(this, type, entry.wrapped, ...args);
              }
            }
            return originalRemoveEventListener.call(this, type, handler, ...args);
          };

          const originalOnIceCandidate = Object.getOwnPropertyDescriptor(
            Object.getPrototypeOf(pc), 
            'onicecandidate'
          );
          
          let userHandler = null;
          
          Object.defineProperty(pc, 'onicecandidate', {
            get: function() {
              return userHandler;
            },
            set: function(handler) {
              userHandler = handler;
              
              if (handler) {
                originalOnIceCandidate.set.call(pc, function(event) {
                  if (event.candidate && event.candidate.candidate) {
                    const candidateStr = event.candidate.candidate;
                    
                    if (candidateStr.includes('typ host') || candidateStr.includes('typ srflx') || candidateStr.includes('typ relay')) {
                      if (debug) console.log('[404-SPOOF] Blocked WebRTC candidate (onicecandidate):', candidateStr.substring(0, 50) + '...');
                      return; 
                    }
                  }
                  
                  if (event.candidate === null) {
                    handler.call(this, event);
                  }
                });
              } else {
                originalOnIceCandidate.set.call(pc, null);
              }
            },
            configurable: true,
            enumerable: true
          });

          return pc;
        };

        Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTCPeerConnection);
        window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
      }

      if (window.webkitRTCPeerConnection && window.webkitRTCPeerConnection !== window.RTCPeerConnection) {
        window.webkitRTCPeerConnection = window.RTCPeerConnection;
      }

      if (debug) console.log('[404-SPOOF] ✓ WebRTC protection applied (local IP leak blocked)');
    } catch (e) {
      console.error('[404-SPOOF] WebRTC protection error:', e);
    }
  }

  if (config.enable_performance_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying performance spoofing...');

      let perfOffset = 0;
      const seedStr = config.name || 'default';
      for (let i = 0; i < seedStr.length; i++) {
        perfOffset += seedStr.charCodeAt(i);
      }
      perfOffset = (perfOffset % 100) + 10; 

      const originalNow = Performance.prototype.now;
      Performance.prototype.now = function() {
        return originalNow.call(this) + perfOffset;
      };

      if (window.performance && window.performance.timing) {
        const originalTiming = window.performance.timing;
        const jitteredCache = {};

        Object.defineProperty(window.performance, 'timing', {
          get: function() {
            return new Proxy(originalTiming, {
              get: function(target, prop) {
                if (typeof target[prop] === 'number' && target[prop] > 0) {
                  if (!jitteredCache[prop]) {
                    const jitter = (Math.random() * 10) - 5; 
                    jitteredCache[prop] = target[prop] + jitter;
                  }
                  return jitteredCache[prop];
                }
                return target[prop];
              }
            });
          },
          configurable: true
        });
      }

      if (debug) console.log('[404-SPOOF] ✓ Performance spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Performance spoofing error:', e);
    }
  }

  if (config.enable_plugin_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying plugin spoofing...');

      const isFirefox = config.browser_type === 'firefox';

      const plugins = [];
      const mimeTypes = [];

      if (isFirefox) {

        const pdfPlugin = {
          name: 'PDF Viewer',
          description: 'Portable Document Format',
          filename: 'internal-pdf-viewer',
          length: 2
        };
        plugins.push(pdfPlugin);

        const pdfMime1 = {
          type: 'application/pdf',
          suffixes: 'pdf',
          description: 'Portable Document Format',
          enabledPlugin: pdfPlugin
        };
        const pdfMime2 = {
          type: 'text/pdf',
          suffixes: 'pdf',
          description: 'Portable Document Format',
          enabledPlugin: pdfPlugin
        };
        mimeTypes.push(pdfMime1, pdfMime2);
      } else {

        const chromePlugin = {
          name: 'Chrome PDF Plugin',
          description: 'Portable Document Format',
          filename: 'internal-pdf-viewer',
          length: 2
        };
        const pdfPlugin = {
          name: 'PDF Viewer',
          description: 'Portable Document Format',
          filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
          length: 1
        };
        plugins.push(chromePlugin, pdfPlugin);

        const chromePdfMime = {
          type: 'application/pdf',
          suffixes: 'pdf',
          description: 'Portable Document Format',
          enabledPlugin: chromePlugin
        };
        const pdfMime = {
          type: 'application/x-google-chrome-pdf',
          suffixes: 'pdf',
          description: 'Portable Document Format',
          enabledPlugin: pdfPlugin
        };
        mimeTypes.push(chromePdfMime, pdfMime);
      }

      Object.defineProperty(Navigator.prototype, 'plugins', {
        get: function() {
          return Object.assign(plugins, {
            item: function(index) { return plugins[index] || null; },
            namedItem: function(name) { 
              return plugins.find(p => p.name === name) || null;
            },
            refresh: function() {}
          });
        },
        configurable: true
      });

      Object.defineProperty(Navigator.prototype, 'mimeTypes', {
        get: function() {
          return Object.assign(mimeTypes, {
            item: function(index) { return mimeTypes[index] || null; },
            namedItem: function(type) {
              return mimeTypes.find(m => m.type === type) || null;
            }
          });
        },
        configurable: true
      });

      if (debug) console.log('[404-SPOOF] ✓ Plugin spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Plugin spoofing error:', e);
    }
  }

  if (config.enable_storage_spoof) {
    try {
      if (debug) console.log('[404-SPOOF] Applying storage spoofing...');

      if (navigator.storage && navigator.storage.estimate) {
        navigator.storage.estimate = function() {
          return Promise.resolve({
            quota: config.storage_quota || 107374182400, 
            usage: Math.floor((config.storage_quota || 107374182400) * 0.1), 
            usageDetails: {
              indexedDB: Math.floor((config.storage_quota || 107374182400) * 0.05),
              caches: Math.floor((config.storage_quota || 107374182400) * 0.03),
              serviceWorkerRegistrations: Math.floor((config.storage_quota || 107374182400) * 0.02)
            }
          });
        };
      }

      if (debug) console.log('[404-SPOOF] ✓ Storage spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Storage spoofing error:', e);
    }
  }

  if (config.enable_coherence_validation !== false && debug) {
    
    console.log('[404-SPOOF] Validating Profile Coherence');
    

    const ua = config.user_agent || '';
    const platform = config.platform || '';
    const vendor = config.vendor || '';
    const browserType = config.browser_type || '';

    let coherenceErrors = 0;

    if (ua.includes('Windows') && !platform.includes('Win')) {
      console.error('[404-SPOOF] INCOHERENCE: Windows UA but non-Windows platform!');
      console.error('[404-SPOOF]   UA:', ua.substring(0, 60) + '...');
      console.error('[404-SPOOF]   Platform:', platform);
      coherenceErrors++;
    }

    if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
      console.error('[404-SPOOF] INCOHERENCE: Mac UA but non-Mac platform!');
      console.error('[404-SPOOF]   UA:', ua.substring(0, 60) + '...');
      console.error('[404-SPOOF]   Platform:', platform);
      coherenceErrors++;
    }

    if (ua.includes('Linux') && !platform.includes('Linux')) {
      console.error('[404-SPOOF] INCOHERENCE: Linux UA but non-Linux platform!');
      console.error('[404-SPOOF]   UA:', ua.substring(0, 60) + '...');
      console.error('[404-SPOOF]   Platform:', platform);
      coherenceErrors++;
    }

    if ((ua.includes('Chrome') || ua.includes('Chromium') || ua.includes('Edg')) && 
        browserType === 'chrome' && vendor !== 'Google Inc.' && vendor !== undefined) {
      console.error('[404-SPOOF] INCOHERENCE: Chrome UA but wrong vendor!');
      console.error('[404-SPOOF]   UA:', ua.substring(0, 60) + '...');
      console.error('[404-SPOOF]   Vendor:', vendor, '(expected: Google Inc.)');
      coherenceErrors++;
    }

    if (ua.includes('Firefox') && browserType === 'firefox' && vendor !== '' && vendor !== undefined) {
      console.error('[404-SPOOF] INCOHERENCE: Firefox UA but non-empty vendor!');
      console.error('[404-SPOOF]   UA:', ua.substring(0, 60) + '...');
      console.error('[404-SPOOF]   Vendor:', vendor, '(expected: empty string)');
      coherenceErrors++;
    }

    if (browserType === 'firefox' && config.sec_ch_ua) {
      console.warn('[404-SPOOF] WARNING: Firefox profile has Client Hints (will be ignored)');
    }

    if (config.screen_resolution) {
      const screenMatch = config.screen_resolution.match(/^(\d+)x(\d+)$/);
      if (!screenMatch) {
        console.error('[404-SPOOF] INCOHERENCE: Invalid screen resolution format!');
        console.error('[404-SPOOF]   Got:', config.screen_resolution);
        console.error('[404-SPOOF]   Expected: WIDTHxHEIGHT (e.g., 1920x1080)');
        coherenceErrors++;
      }
    }

    if (config.hardware_concurrency && (config.hardware_concurrency < 1 || config.hardware_concurrency > 128)) {
      console.warn('[404-SPOOF] WARNING: Unusual hardwareConcurrency:', config.hardware_concurrency);
    }

    if (config.device_memory && ![0.25, 0.5, 1, 2, 4, 8, 16, 32, 64].includes(config.device_memory)) {
      console.warn('[404-SPOOF] WARNING: Unusual deviceMemory:', config.device_memory);
    }

    if (coherenceErrors === 0) {
      console.log('[404-SPOOF] ✓ Profile coherence validated (0 errors)');
    } else {
      console.error('[404-SPOOF] ✗ Profile coherence validation FAILED!');
      console.error('[404-SPOOF] ✗', coherenceErrors, 'coherence error(s) detected');
      console.error('[404-SPOOF] ✗ This WILL cause fingerprint detection!');
      console.error('[404-SPOOF] ✗ Fix your profile in profiles.json');
    }

    
  }

  if (config.enable_media_devices_spoof !== false && navigator.mediaDevices) {
    try {
      if (debug) console.log('[404-SPOOF] Applying MediaDevices spoofing...');

      const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;

      navigator.mediaDevices.enumerateDevices = function enumerateDevices() {
        return Promise.resolve([
          {
            deviceId: 'default',
            kind: 'audioinput',
            label: 'Default - Microphone Array',
            groupId: 'default-audio-group'
          },
          {
            deviceId: 'default',
            kind: 'audiooutput',
            label: 'Default - Speakers',
            groupId: 'default-audio-group'
          },
          {
            deviceId: 'default',
            kind: 'videoinput',
            label: 'Default - HD Webcam',
            groupId: 'default-video-group'
          }
        ]);
      };

      if (debug) console.log('[404-SPOOF] ✓ MediaDevices spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] MediaDevices spoofing error:', e);
    }
  }

  if (config.enable_gamepad_spoof !== false && navigator.getGamepads) {
    try {
      if (debug) console.log('[404-SPOOF] Applying Gamepad API spoofing...');

      navigator.getGamepads = function getGamepads() {
        return []; 
      };

      if (debug) console.log('[404-SPOOF] ✓ Gamepad API spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Gamepad spoofing error:', e);
    }
  }

  if (config.enable_event_timing_spoof !== false) {
    try {
      if (debug) console.log('[404-SPOOF] Applying event timing jitter...');

      const originalTimeStamp = Object.getOwnPropertyDescriptor(Event.prototype, 'timeStamp');
      if (originalTimeStamp && originalTimeStamp.get) {
        Object.defineProperty(Event.prototype, 'timeStamp', {
          get: function() {
            const real = originalTimeStamp.get.call(this);

            const jitter = (Math.random() - 0.5) * 10;
            return real + jitter;
          },
          configurable: true
        });
      }

      if (debug) console.log('[404-SPOOF] ✓ Event timing jitter applied');
    } catch (e) {
      console.error('[404-SPOOF] Event timing jitter error:', e);
    }
  }

  if (config.enable_iframe_protection !== false) {
    try {
      if (debug) console.log('[404-SPOOF] Initializing comprehensive iframe protection (V1-style)');

      const applySpoofing = function(targetWindow) {
        try {

          if (!targetWindow || targetWindow.__fpSpoofed) {
            return;
          }

          try {
            const test = targetWindow.location.href;
          } catch (e) {
            if (debug) console.log('[404-SPOOF] Skipping cross-origin iframe:', e.message);
            return;
          }

          targetWindow.__fpSpoofed = true;
          targetWindow.__fpConfig = config;
          targetWindow.__404_advanced_protections_active = true;

          if (debug) console.log('[404-SPOOF] Applying comprehensive spoofing to iframe:', targetWindow.location.href);

          if (config.enable_headers_spoof) {
            const safeDefine = function(obj, prop, descriptor) {
              try {
                Object.defineProperty(obj, prop, descriptor);
              } catch (e) {
                if (debug) console.warn('[404-SPOOF] Could not define', prop, ':', e.message);
              }
            };

            safeDefine(targetWindow.navigator, 'userAgent', {
              get: function() { return config.user_agent; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.navigator, 'platform', {
              get: function() { return config.platform; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.navigator, 'vendor', {
              get: function() { return config.vendor || ''; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.navigator, 'hardwareConcurrency', {
              get: function() { return config.hardware_concurrency; },
              enumerable: true,
              configurable: true
            });

            if (config.device_memory) {
              safeDefine(targetWindow.navigator, 'deviceMemory', {
                get: function() { return config.device_memory; },
                enumerable: true,
                configurable: true
              });
            }

            safeDefine(targetWindow.navigator, 'languages', {
              get: function() { return config.languages || ["en-US", "en"]; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.navigator, 'language', {
              get: function() { return (config.languages || ["en-US"])[0]; },
              enumerable: true,
              configurable: true
            });
          }

          if (config.enable_canvas_spoof && config.screen_resolution) {
            const safeDefine = function(obj, prop, descriptor) {
              try {
                Object.defineProperty(obj, prop, descriptor);
              } catch (e) {
                if (debug) console.warn('[404-SPOOF] Could not define', prop, ':', e.message);
              }
            };

            const [width, height] = config.screen_resolution.split('x').map(Number);

            safeDefine(targetWindow.screen, 'width', {
              get: function() { return width; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.screen, 'height', {
              get: function() { return height; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.screen, 'availWidth', {
              get: function() { return config.screen_avail_width || width; },
              enumerable: true,
              configurable: true
            });

            safeDefine(targetWindow.screen, 'availHeight', {
              get: function() { return config.screen_avail_height || (height - 40); },
              enumerable: true,
              configurable: true
            });
          }

          if (config.enable_automation_evasion) {
            const safeDefine = function(obj, prop, descriptor) {
              try {
                Object.defineProperty(obj, prop, descriptor);
              } catch (e) {
                if (debug) console.warn('[404-SPOOF] Could not define', prop, ':', e.message);
              }
            };

            safeDefine(targetWindow.navigator, 'webdriver', {
              get: function() { return false; },
              enumerable: true,
              configurable: true
            });

            if (targetWindow.navigator.chrome) {
              targetWindow.navigator.chrome.runtime = undefined;
            }

            delete targetWindow.document.__selenium_unwrapped;
            delete targetWindow.document.__webdriver_evaluate;
            delete targetWindow.document.__selenium_evaluate;
            delete targetWindow.document.__fxdriver_evaluate;
            delete targetWindow.document.__driver_unwrapped;
            delete targetWindow.document.__webdriver_unwrapped;
            delete targetWindow.document.__driver_evaluate;
            delete targetWindow.document.__fxdriver_unwrapped;
          }

          if (config.enable_canvas_spoof && targetWindow.HTMLCanvasElement) {

            const originalToDataURL = targetWindow.HTMLCanvasElement.prototype.toDataURL;
            const originalToBlob = targetWindow.HTMLCanvasElement.prototype.toBlob;
            const originalGetImageData = targetWindow.CanvasRenderingContext2D.prototype.getImageData;

            targetWindow.applyCanvasNoise = applyCanvasNoise;
            targetWindow.hashString = hashString;
            targetWindow.sessionCanvasHash = sessionCanvasHash;

            if (debug) console.log('[404-SPOOF] [IFRAME] Overriding canvas methods (toDataURL/toBlob/getImageData)');

            targetWindow.CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
              const imageData = originalGetImageData.call(this, sx, sy, sw, sh);
              if (config.enable_canvas_spoof) {
                applyCanvasNoise(imageData);
                if (debug) console.log('[404-SPOOF] [IFRAME] getImageData noise applied:', imageData.width + 'x' + imageData.height);
              }
              return imageData;
            };

            targetWindow.HTMLCanvasElement.prototype.toDataURL = function() {
              if (!config.enable_canvas_spoof) {
                return originalToDataURL.apply(this, arguments);
              }

              try {
                const ctx = this.getContext('2d');
                if (!ctx) {
                  return originalToDataURL.apply(this, arguments);
                }

                if (debug) console.log('[404-SPOOF] [IFRAME] toDataURL called:', this.width + 'x' + this.height);

                const imageData = originalGetImageData.call(ctx, 0, 0, this.width, this.height);

                const backup = new Uint8ClampedArray(imageData.data);

                applyCanvasNoise(imageData);

                ctx.putImageData(imageData, 0, 0);

                const dataURL = originalToDataURL.apply(this, arguments);

                imageData.data.set(backup);
                ctx.putImageData(imageData, 0, 0);

                if (debug) console.log('[404-SPOOF] [IFRAME] toDataURL completed with noise');

                return dataURL;
              } catch (e) {
                if (debug) console.error('[404-SPOOF] [IFRAME] toDataURL error:', e);
                return originalToDataURL.apply(this, arguments);
              }
            };

            targetWindow.HTMLCanvasElement.prototype.toBlob = function(callback) {
              if (!config.enable_canvas_spoof) {
                return originalToBlob.apply(this, arguments);
              }

              try {
                const ctx = this.getContext('2d');
                if (!ctx) {
                  return originalToBlob.apply(this, arguments);
                }

                if (debug) console.log('[404-SPOOF] [IFRAME] toBlob called:', this.width + 'x' + this.height);

                const imageData = originalGetImageData.call(ctx, 0, 0, this.width, this.height);

                const backup = new Uint8ClampedArray(imageData.data);

                applyCanvasNoise(imageData);

                ctx.putImageData(imageData, 0, 0);

                const wrappedCallback = function(blob) {

                  imageData.data.set(backup);
                  ctx.putImageData(imageData, 0, 0);

                  if (debug) console.log('[404-SPOOF] [IFRAME] toBlob completed with noise');

                  if (callback) callback(blob);
                };

                return originalToBlob.call(this, wrappedCallback, arguments[1], arguments[2]);
              } catch (e) {
                if (debug) console.error('[404-SPOOF] [IFRAME] toBlob error:', e);
                return originalToBlob.apply(this, arguments);
              }
            };
          }

          if (config.enable_webgl_spoof && targetWindow.WebGLRenderingContext) {
            const originalGetParameter = targetWindow.WebGLRenderingContext.prototype.getParameter;

            targetWindow.WebGLRenderingContext.prototype.getParameter = function(parameter) {
              if (parameter === 0x1F00) return config.webgl_vendor || "Google Inc. (Intel)";
              if (parameter === 0x1F01) return config.webgl_renderer || "ANGLE (Intel)";
              return originalGetParameter.call(this, parameter);
            };

            if (targetWindow.WebGL2RenderingContext) {
              targetWindow.WebGL2RenderingContext.prototype.getParameter = 
                targetWindow.WebGLRenderingContext.prototype.getParameter;
            }
          }

          if (debug) console.log('[404-SPOOF] [IFRAME] Successfully spoofed with full canvas protection');

        } catch (e) {
          if (debug) console.error('[404-SPOOF] [IFRAME] Error spoofing iframe:', e);
        }
      };

      const patchAllFrames = function(rootWindow) {
        try {
          applySpoofing(rootWindow);

          if (rootWindow.frames && rootWindow.frames.length > 0) {
            for (let i = 0; i < rootWindow.frames.length; i++) {
              try {
                patchAllFrames(rootWindow.frames[i]);
              } catch (e) {

              }
            }
          }
        } catch (e) {
          if (debug) console.error('[404-SPOOF] Error in patchAllFrames:', e);
        }
      };

      patchAllFrames(window);

      const iframeObserver = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
          mutation.addedNodes.forEach(function(node) {
            if (node.tagName === 'IFRAME') {
              if (debug) console.log('[404-SPOOF] New iframe detected via MutationObserver');

              node.addEventListener('load', function() {
                try {
                  patchAllFrames(node.contentWindow);
                } catch (e) {
                  if (debug) console.error('[404-SPOOF] Error patching new iframe:', e);
                }
              });
            }

            if (node.querySelectorAll) {
              node.querySelectorAll('iframe').forEach(function(iframe) {
                if (debug) console.log('[404-SPOOF] Nested iframe detected');

                iframe.addEventListener('load', function() {
                  try {
                    patchAllFrames(iframe.contentWindow);
                  } catch (e) {
                    if (debug) console.error('[404-SPOOF] Error patching nested iframe:', e);
                  }
                });
              });
            }
          });
        });
      });

      iframeObserver.observe(document.documentElement, {
        childList: true,
        subtree: true
      });

      const originalCreateElement = document.createElement;
      document.createElement = function(tagName) {
        const element = originalCreateElement.call(document, tagName);

        if (tagName && tagName.toLowerCase() === 'iframe') {
          if (debug) console.log('[404-SPOOF] iframe created via createElement');

          element.addEventListener('load', function() {
            try {
              patchAllFrames(element.contentWindow);
            } catch (e) {
              if (debug) console.error('[404-SPOOF] Error patching createElement iframe:', e);
            }
          });
        }

        return element;
      };

      if (debug) console.log('[404-SPOOF] ✓ Comprehensive iframe protection active (V1-style with full canvas overrides)');

    } catch (e) {
      console.error('[404-SPOOF] Iframe protection error:', e);
    }
  }

  if (config.enable_automation_evasion) {
    try {
      if (debug) console.log('[404-SPOOF] Applying comprehensive automation evasion...');

      const automationProps = [
        '__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function',
        '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate',
        '__driver_unwrapped', '__webdriver_unwrapped', '__driver_evaluate',
        '__selenium_unwrapped', '__fxdriver_unwrapped', '__nightmare',
        'phantom', '__phantomjs', 'callPhantom', '_phantom', '_Selenium_IDE_Recorder',
        'callSelenium', '_selenium', 'selenium', '__selenium', '__webdriver',
        'domAutomation', 'domAutomationController', '$cdc_asdjflasutopfhvcZLmcfl_',
        '$chrome_asyncScriptInfo', '__$webdriverAsyncExecutor', 'webdriver',
        '__driver', '__webdriver_script_fn', 'awesomium', 'PERSISTENT',
        'wdclient', 'jest', 'puppeteer', '__puppeteer', 'playwright', '__playwright'
      ];

      automationProps.forEach(prop => {
        try {
          if (window[prop]) {
            delete window[prop];
          }
          Object.defineProperty(window, prop, {
            get: () => undefined,
            set: () => undefined,
            configurable: false
          });
        } catch (e) {}
      });

      const docAutomationProps = ['webdriver', '__webdriver_evaluate', '__driver_evaluate'];
      docAutomationProps.forEach(prop => {
        try {
          if (document[prop]) {
            delete document[prop];
          }
          Object.defineProperty(document, prop, {
            get: () => undefined,
            configurable: false
          });
        } catch (e) {}
      });

      if (document.hasFocus) {
        const originalHasFocus = document.hasFocus;
        document.hasFocus = function() {
          return true;
        };
        document.hasFocus.toString = function() {
          return originalHasFocus.toString();
        };
      }

      Object.defineProperty(document, 'visibilityState', {
        get: () => 'visible',
        configurable: true
      });

      Object.defineProperty(document, 'hidden', {
        get: () => false,
        configurable: true
      });

      const isChromium = config.browser_type === 'chrome' || config.browser_type === 'edge';
      const isFirefox = config.browser_type === 'firefox';
      
      if (isChromium && !window.chrome) {
        window.chrome = {
          runtime: {
            OnInstalledReason: {
              CHROME_UPDATE: "chrome_update",
              INSTALL: "install",
              SHARED_MODULE_UPDATE: "shared_module_update",
              UPDATE: "update"
            },
            OnRestartRequiredReason: {
              APP_UPDATE: "app_update",
              OS_UPDATE: "os_update",
              PERIODIC: "periodic"
            },
            PlatformArch: {
              ARM: "arm",
              MIPS: "mips",
              MIPS64: "mips64",
              X86_32: "x86-32",
              X86_64: "x86-64"
            },
            PlatformNaclArch: {
              ARM: "arm",
              MIPS: "mips",
              MIPS64: "mips64",
              X86_32: "x86-32",
              X86_64: "x86-64"
            },
            PlatformOs: {
              ANDROID: "android",
              CROS: "cros",
              LINUX: "linux",
              MAC: "mac",
              OPENBSD: "openbsd",
              WIN: "win"
            },
            RequestUpdateCheckStatus: {
              NO_UPDATE: "no_update",
              THROTTLED: "throttled",
              UPDATE_AVAILABLE: "update_available"
            }
          },
          csi: function() {},
          loadTimes: function() {}
        };
      }


      if (isFirefox && window.chrome) {
        try {
          delete window.chrome;
          Object.defineProperty(window, 'chrome', {
            get: () => undefined,
            configurable: false
          });
          if (debug) console.log('[404-SPOOF] Removed window.chrome for Firefox profile');
        } catch (e) {
          console.warn('[404-SPOOF] Could not remove window.chrome:', e);
        }
      }

      if (window.navigator && window.navigator.webdriver) {
        try {
          delete window.navigator.webdriver;
        } catch (e) {}
      }

      if (debug) console.log('[404-SPOOF] ✓ Comprehensive automation evasion applied');
    } catch (e) {
      console.error('[404-SPOOF] Automation evasion error:', e);
    }
  }

  if (config.enable_automation_evasion) {
    try {
      if (debug) console.log('[404-SPOOF] Applying geolocation spoofing...');

      if (navigator.geolocation) {
        const errorCallback = function(error) {
          if (error && typeof error === 'function') {
            error({
              code: 1,
              message: 'User denied Geolocation',
              PERMISSION_DENIED: 1,
              POSITION_UNAVAILABLE: 2,
              TIMEOUT: 3
            });
          }
        };

        navigator.geolocation.getCurrentPosition = function(success, error) {
          errorCallback(error);
        };

        navigator.geolocation.watchPosition = function(success, error) {
          errorCallback(error);
          return Math.floor(Math.random() * 10000);
        };

        navigator.geolocation.clearWatch = function() {};
      }

      if (debug) console.log('[404-SPOOF] ✓ Geolocation spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Geolocation spoofing error:', e);
    }
  }

  if (config.enable_speech_synthesis_spoof && window.speechSynthesis) {
    try {
      if (debug) console.log('[404-SPOOF] Applying speech synthesis spoofing...');

      const isFirefox = config.browser_type === 'firefox';
      

      const primaryLang = config.languages && config.languages[0] ? config.languages[0] : 'en-US';

      const voices = [];

      if (isFirefox) {

        voices.push(
          { voiceURI: `urn:moz-tts:sapi:Microsoft David Desktop - English (United States)?${primaryLang}`, name: 'Microsoft David Desktop - English (United States)', lang: primaryLang, localService: true, default: true },
          { voiceURI: `urn:moz-tts:sapi:Microsoft Zira Desktop - English (United States)?${primaryLang}`, name: 'Microsoft Zira Desktop - English (United States)', lang: primaryLang, localService: true, default: false }
        );
      } else {

        voices.push(
          { voiceURI: 'Google US English', name: 'Google US English', lang: primaryLang, localService: false, default: true },
          { voiceURI: `Microsoft David - English (United States)`, name: `Microsoft David - English (United States)`, lang: primaryLang, localService: true, default: false },
          { voiceURI: `Microsoft Zira - English (United States)`, name: `Microsoft Zira - English (United States)`, lang: primaryLang, localService: true, default: false }
        );
      }

      voices.forEach(v => Object.freeze(v));

      window.speechSynthesis.getVoices = function() {
        return voices;
      };

      Object.defineProperty(window.speechSynthesis, 'onvoiceschanged', {
        get: () => null,
        set: () => {},
        configurable: true
      });

      if (debug) console.log('[404-SPOOF] ✓ Speech synthesis spoofing applied (language consistent:', primaryLang, ')');
    } catch (e) {
      console.error('[404-SPOOF] Speech synthesis spoofing error:', e);
    }
  }

  if (config.enable_network_spoof && navigator.connection) {
    try {
      if (debug) console.log('[404-SPOOF] Applying network spoofing...');

      const spoofedConnection = {
        effectiveType: '4g',
        downlink: 10,
        rtt: 50,
        saveData: false,
        onchange: null,
        addEventListener: function() {},
        removeEventListener: function() {},
        dispatchEvent: function() { return true; }
      };

      Object.defineProperty(Navigator.prototype, 'connection', {
        get: () => spoofedConnection,
        configurable: true
      });

      if (navigator.mozConnection) {
        Object.defineProperty(Navigator.prototype, 'mozConnection', {
          get: () => spoofedConnection,
          configurable: true
        });
      }

      if (navigator.webkitConnection) {
        Object.defineProperty(Navigator.prototype, 'webkitConnection', {
          get: () => spoofedConnection,
          configurable: true
        });
      }

      if (debug) console.log('[404-SPOOF] ✓ Network spoofing applied');
    } catch (e) {
      console.error('[404-SPOOF] Network spoofing error:', e);
    }
  }

  if (config.enable_font_spoof && config.fonts && Array.isArray(config.fonts)) {
    try {
      const spoofedFonts = config.fonts;
      const fallbackFonts = ['monospace', 'sans-serif', 'serif', 'cursive', 'fantasy'];

      if (debug) console.log(`[404-SPOOF] Applying font protection (${spoofedFonts.length} fonts)...`);

      if (document.fonts) {
        const originalDocumentFonts = document.fonts;
        
        Object.defineProperty(document, 'fonts', {
          get: function() {
            const mockFontFaces = spoofedFonts.map(fontName => ({
              family: fontName,
              style: 'normal',
              weight: '400',
              stretch: 'normal',
              unicodeRange: 'U+0-10FFFF',
              variant: 'normal',
              featureSettings: 'normal',
              display: 'auto',
              ascentOverride: 'normal',
              descentOverride: 'normal',
              lineGapOverride: 'normal',
              status: 'loaded',
              loaded: Promise.resolve()
            }));

            const mockFontFaceSet = {
              size: spoofedFonts.length,
              ready: Promise.resolve(this),
              status: 'loaded',

              check: function(font, text) {
                const fontFamily = font.match(/['"]?([^'"]+)['"]?/);
                if (fontFamily && fontFamily[1]) {
                  const cleanName = fontFamily[1].trim();
                  return spoofedFonts.includes(cleanName) || fallbackFonts.includes(cleanName);
                }
                return false;
              },

              load: function(font, text) {
                return Promise.resolve([]);
              },

              has: function(fontFace) {
                if (fontFace && fontFace.family) {
                  return spoofedFonts.includes(fontFace.family);
                }
                return false;
              },

              add: function(fontFace) { return this; },
              delete: function(fontFace) { return false; },
              clear: function() {},

              entries: function() { 
                let index = 0;
                return {
                  next: () => {
                    if (index < mockFontFaces.length) {
                      return { value: [mockFontFaces[index], mockFontFaces[index++]], done: false };
                    }
                    return { done: true };
                  },
                  [Symbol.iterator]: function() { return this; }
                };
              },
              
              forEach: function(callback) {
                mockFontFaces.forEach((fontFace, index) => {
                  callback(fontFace, fontFace, this);
                });
              },
              
              keys: function() { 
                let index = 0;
                return {
                  next: () => {
                    if (index < mockFontFaces.length) {
                      return { value: mockFontFaces[index++], done: false };
                    }
                    return { done: true };
                  },
                  [Symbol.iterator]: function() { return this; }
                };
              },
              
              values: function() { 
                let index = 0;
                return {
                  next: () => {
                    if (index < mockFontFaces.length) {
                      return { value: mockFontFaces[index++], done: false };
                    }
                    return { done: true };
                  },
                  [Symbol.iterator]: function() { return this; }
                };
              },
              
              [Symbol.iterator]: function() { 
                return this.values();
              }
            };

            return mockFontFaceSet;
          },
          enumerable: true,
          configurable: true
        });
      }

      const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
      
      const hashFontName = (fontName) => {
        let hash = 0;
        for (let i = 0; i < fontName.length; i++) {
          hash = ((hash << 5) - hash) + fontName.charCodeAt(i);
          hash = hash & hash;
        }
        return Math.abs(hash);
      };

      // PRNG for measureText timing noise (consistent per session)
      const measureTextPRNG = createPRNG('measuretext_timing_' + window.__404_session_id);

      CanvasRenderingContext2D.prototype.measureText = function(text) {
        const originalResult = originalMeasureText.call(this, text);
        
        const currentFont = this.font || '10px sans-serif';
        const fontMatch = currentFont.match(/(?:['"]([^'"]+)['"]|([^\s,]+))(?:\s*,|\s*$)/);

        if (!fontMatch) {
          return originalResult;
        }

        const requestedFont = (fontMatch[1] || fontMatch[2]).trim().toLowerCase();
        
        if (fallbackFonts.includes(requestedFont)) {
          return originalResult;
        }

        if (spoofedFonts.some(f => f.toLowerCase() === requestedFont)) {
          const baseWidth = text.length * 7.5; 
          const fontHash = hashFontName(requestedFont);
          const jitter = (fontHash % 100) / 100; 
          
          // Add sub-pixel timing noise to width (affects font preference fingerprint)
          const timingNoise = (measureTextPRNG() - 0.5) * 0.0001; 
          return {
            width: baseWidth + jitter + timingNoise,
            actualBoundingBoxLeft: 0,
            actualBoundingBoxRight: baseWidth + jitter + timingNoise,
            fontBoundingBoxAscent: 10,
            fontBoundingBoxDescent: 2,
            actualBoundingBoxAscent: 9,
            actualBoundingBoxDescent: 2,
            emHeightAscent: 10,
            emHeightDescent: 2,
            hangingBaseline: 8,
            alphabeticBaseline: 0,
            ideographicBaseline: -2
          };
        }

        const fallbackFont = currentFont.replace(new RegExp(fontMatch[0], 'gi'), 'monospace');
        const savedFont = this.font;
        this.font = fallbackFont;
        const fallbackMetrics = originalMeasureText.call(this, text);
        this.font = savedFont;

        return fallbackMetrics;
      };

      if (debug) console.log(`[404-SPOOF] ✓ Font protection applied (${spoofedFonts.length} fonts, enumeration blocked)`);
    } catch (e) {
      console.error('[404-SPOOF] Font protection error:', e);
    }
  }

  if (config.enable_viewport_spoof && window.self === window.top) {
    try {
      if (debug) console.log('[404-SPOOF] Applying viewport spoofing (main window only)...');

      const rounding = config.viewport_rounding || 200;

      function roundDimension(value, min) {

        if (typeof value !== 'number' || isNaN(value)) {
          return min;
        }
        const rounded = Math.ceil(value / rounding) * rounding;
        return Math.max(rounded, min);
      }

      const realInnerWidth = window.innerWidth;
      const realInnerHeight = window.innerHeight;
      const realOuterWidth = window.outerWidth;
      const realOuterHeight = window.outerHeight;

      if (typeof realInnerWidth !== 'number' || typeof realInnerHeight !== 'number') {
        console.warn('[404-SPOOF] Cannot apply viewport spoofing - invalid dimensions');
        return;
      }

      const spoofedInnerWidth = roundDimension(realInnerWidth, 800);
      const spoofedInnerHeight = roundDimension(realInnerHeight, 600);
      const spoofedOuterWidth = roundDimension(realOuterWidth, 800);
      const spoofedOuterHeight = roundDimension(realOuterHeight, 600);

      Object.defineProperty(window, 'innerWidth', {
        get: function() { return spoofedInnerWidth; },
        configurable: true,
        enumerable: true
      });

      Object.defineProperty(window, 'innerHeight', {
        get: function() { return spoofedInnerHeight; },
        configurable: true,
        enumerable: true
      });

      Object.defineProperty(window, 'outerWidth', {
        get: function() { return spoofedOuterWidth; },
        configurable: true,
        enumerable: true
      });

      Object.defineProperty(window, 'outerHeight', {
        get: function() { return spoofedOuterHeight; },
        configurable: true,
        enumerable: true
      });

      if (window.visualViewport) {
        try {
          Object.defineProperty(window.visualViewport, 'width', {
            get: function() { return spoofedInnerWidth; },
            configurable: true,
            enumerable: true
          });

          Object.defineProperty(window.visualViewport, 'height', {
            get: function() { return spoofedInnerHeight; },
            configurable: true,
            enumerable: true
          });
        } catch (e) {
          if (debug) console.warn('[404-SPOOF] Could not override visualViewport:', e);
        }
      }

      try {
        Object.defineProperty(document.documentElement, 'clientWidth', {
          get: function() { return spoofedInnerWidth; },
          configurable: true,
          enumerable: true
        });

        Object.defineProperty(document.documentElement, 'clientHeight', {
          get: function() { return spoofedInnerHeight; },
          configurable: true,
          enumerable: true
        });
      } catch (e) {
        if (debug) console.warn('[404-SPOOF] Could not override documentElement dimensions:', e);
      }

      if (debug) {
        console.log(`[404-SPOOF] ✓ Viewport spoofing applied: ${realInnerWidth}x${realInnerHeight} → ${spoofedInnerWidth}x${spoofedInnerHeight}`);
      }
    } catch (e) {
      console.error('[404-SPOOF] Viewport spoofing error:', e);
    }
  }


  if (config.enable_dom_measurement_noise !== false) {
    try {
      const domNoisePRNG = createPRNG('dom_noise_' + window.__404_session_id);
      
      // Hook Element.prototype.getBoundingClientRect
      const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = function() {
        const rect = originalGetBoundingClientRect.call(this);
        
        // Add sub-pixel noise (±0.00001px - imperceptible)
        const noise = () => (domNoisePRNG() - 0.5) * 0.00002;
        
        return {
          top: rect.top + noise(),
          right: rect.right + noise(),
          bottom: rect.bottom + noise(),
          left: rect.left + noise(),
          width: rect.width + noise(),
          height: rect.height + noise(),
          x: rect.x + noise(),
          y: rect.y + noise(),
          toJSON: rect.toJSON.bind(rect)
        };
      };
      
      // Hook offsetWidth/offsetHeight getters
      const originalOffsetWidthDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
      const originalOffsetHeightDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
      
      if (originalOffsetWidthDesc && originalOffsetWidthDesc.get) {
        Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
          get: function() {
            const original = originalOffsetWidthDesc.get.call(this);
            const noise = (domNoisePRNG() - 0.5) * 0.00002;
            return original + noise;
          },
          configurable: true,
          enumerable: true
        });
      }
      
      if (originalOffsetHeightDesc && originalOffsetHeightDesc.get) {
        Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
          get: function() {
            const original = originalOffsetHeightDesc.get.call(this);
            const noise = (domNoisePRNG() - 0.5) * 0.00002;
            return original + noise;
          },
          configurable: true,
          enumerable: true
        });
      }
      
      if (debug) console.log('[404-SPOOF] ✓ DOM measurement noise enabled (affects fontPreferences, emoji, mathML)');
    } catch (e) {
      console.error('[404-SPOOF] DOM measurement noise error:', e);
    }
  }

  if (!window.__404_canvas_fingerprint) {
    window.__404_canvas_fingerprint = displayCanvasHash;
    Object.defineProperty(window, '__404_canvas_fingerprint', {
      value: displayCanvasHash,
      writable: false,
      enumerable: false,
      configurable: false
    });
    if (debug) console.log('[404-SPOOF] Canvas fingerprint exposed:', displayCanvasHash);
  }

  window.__404_advanced_protections_active = true;
  window.__404_advanced_protections_version = '2.0.0';

  console.log('[404] Fingerprint protections active');

  // Advanced obfuscation: Use Symbols to hide state from Object.keys() enumeration
  // Symbols are non-enumerable and won't appear in for...in or Object.keys()
  // Original __404_* properties remain for backward compatibility with iframe code
  try {
    if (typeof Symbol !== 'undefined') {
      // Create symbol aliases for all runtime-required globals
      window[Symbol.for('bs')] = window.__404_bootstrap_active;
      window[Symbol.for('sh')] = window.__404_shim_active;
      window[Symbol.for('cr')] = window.__404_config_ready;
      window[Symbol.for('pr')] = window.__404_advanced_protections_active;
      window[Symbol.for('sg')] = window.__404_spoofed_globals;
      window[Symbol.for('sid')] = window.__404_session_id;
      window[Symbol.for('cfp')] = window.__404_canvas_fingerprint;
      window[Symbol.for('cfg')] = window.__fpConfig;
      
      if (config.debug) {
        console.log('[404] Symbol aliases created for stealth access');
      }
    }
    
    // Delete version strings (never checked at runtime)
    delete window.__404_bootstrap_version;
    delete window.__404_shim_version;
    delete window.__404_config_version;
    delete window.__404_advanced_protections_version;
    
    // Note: __404_* properties and __fpConfig must remain for runtime functionality -- need to 
    // eval() wrapper checks __404_spoofed_globals, canvas needs __404_session_id, etc.
    // Symbol aliases provide hidden access path for future refactoring
    
    if (config.debug) {
      console.log('[404] Version strings cleaned, core globals remain functional');
    }
  } catch (e) {
  }

})();