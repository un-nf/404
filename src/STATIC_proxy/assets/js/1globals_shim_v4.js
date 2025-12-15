/* STATIC Proxy Globals Shim v4 (AGPL-3.0) */
;(function staticGlobalsShim() {
  'use strict';

  const MARK = '__static_globals_shim_active';
  const LOG = '[STATIC-SHIM]';

  if (window[MARK]) {
    console.warn(LOG, 'already applied');
    return;
  }

  if (!window.__static_bootstrap_active && !window.__404_bootstrap_active) {
    console.error(LOG, 'bootstrap missing, spoofing degraded');
  }

  const native = {
    defineProperty: Object.defineProperty,
    getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
    navigator: window.navigator,
    screen: window.screen,
    performance: window.performance,
    Notification: window.Notification,
  };

  const originalDescriptors = {};
  [
    'navigator',
    'screen',
    'performance',
    'devicePixelRatio',
    'innerWidth',
    'innerHeight',
    'outerWidth',
    'outerHeight',
  ].forEach((key) => {
    const descriptor = native.getOwnPropertyDescriptor(window, key);
    if (descriptor) {
      originalDescriptors[key] = descriptor;
    }
  });

  if (!native.navigator) {
    console.warn(LOG, 'navigator unavailable, aborting');
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

  function getSessionEntropy() {
    return (
      window.__STATIC_SESSION_ID ||
      window.__404_session_id ||
      getConfig().session_id ||
      Math.random().toString(36)
    );
  }

  function createPRNG(seed) {
    const config = getConfig();
    const salt = getSessionEntropy();
    const fullSeed = (config.name || 'static-profile') + (seed || 'seed') + salt;

    let state = 0;
    for (let i = 0; i < fullSeed.length; i += 1) {
      state = ((state << 5) - state) + fullSeed.charCodeAt(i);
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

  function hashString(input) {
    const text = String(input || '');
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return (hash >>> 0).toString(16);
  }

  (function ensureSharedEntropyHelpers() {
    if (typeof window.__static_rng !== 'function') {
      window.__static_rng = function staticRng(seed) {
        return createPRNG(seed);
      };
    }
    if (typeof window.__static_hash !== 'function') {
      window.__static_hash = hashString;
    }
  }());

  function freezeList(list) {
    if (!Array.isArray(list)) {
      return list;
    }
    return Object.freeze(list.slice());
  }

  function createDomException(message, name) {
    if (typeof DOMException === 'function') {
      return new DOMException(message, name);
    }
    const error = new Error(message);
    error.name = name;
    return error;
  }

  function normalizeLangs(config) {
    if (Array.isArray(config.languages)) {
      return freezeList(config.languages);
    }
    if (typeof config.languages === 'string') {
      return freezeList(config.languages.split(',').map((item) => item.trim()).filter(Boolean));
    }
    return freezeList(['en-US', 'en']);
  }

  function resolveVendorValue(config, browserType) {
    if (Object.prototype.hasOwnProperty.call(config, 'vendor')) {
      return config.vendor;
    }
    return browserType === 'firefox' ? '' : 'Google Inc.';
  }

  function resolveVendorFlavors(config, browserType) {
    if (Object.prototype.hasOwnProperty.call(config, 'vendor_flavors')) {
      if (config.vendor_flavors === null) {
        return null;
      }
      const list = Array.isArray(config.vendor_flavors)
        ? config.vendor_flavors.slice()
        : [];
      return Object.freeze(list);
    }
    if (browserType === 'firefox') {
      return null;
    }
    return Object.freeze(['chrome']);
  }

  function parseResolution(value) {
    if (typeof value === 'string') {
      const parts = value.split('x').map((item) => parseInt(item, 10)).filter((num) => Number.isFinite(num));
      if (parts.length === 2) {
        return { width: parts[0], height: parts[1] };
      }
    }
    if (value && typeof value === 'object') {
      const width = parseInt(value.width, 10);
      const height = parseInt(value.height, 10);
      if (Number.isFinite(width) && Number.isFinite(height)) {
        return { width, height };
      }
    }
    return { width: 1920, height: 1080 };
  }

  function deriveViewportMetrics(config) {
    const resolution = parseResolution(config.screen_resolution);
    const fallbackInnerWidth = Math.max(1024, resolution.width - 16);
    const fallbackInnerHeight = Math.max(640, resolution.height - 88);
    return {
      innerWidth: config.window_inner_width || fallbackInnerWidth,
      innerHeight: config.window_inner_height || fallbackInnerHeight,
      outerWidth: config.window_outer_width || resolution.width,
      outerHeight: config.window_outer_height || resolution.height,
      devicePixelRatio: (function resolveDpr() {
        const raw = config.device_pixel_ratio !== undefined ? config.device_pixel_ratio : config.sec_ch_dpr;
        const parsed = parseFloat(raw);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
      }()),
    };
  }

  function normalizeDeviceMemory(value) {
    const allowed = [0.25, 0.5, 1, 2, 4, 8];
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) {
      return 1;
    }
    let closest = allowed[0];
    let delta = Math.abs(allowed[0] - numeric);
    for (let i = 1; i < allowed.length; i += 1) {
      const currentDelta = Math.abs(allowed[i] - numeric);
      if (currentDelta < delta) {
        delta = currentDelta;
        closest = allowed[i];
      }
    }
    return closest;
  }

  function coerceList(value) {
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry).trim()).filter(Boolean);
    }
    if (typeof value === 'string') {
      return value.split(',').map((entry) => entry.trim()).filter(Boolean);
    }
    return [];
  }

  function createArrayLike(entries, keyProp) {
    const arrayLike = [];
    entries.forEach((entry, idx) => {
      arrayLike[idx] = entry;
    });
    Object.defineProperty(arrayLike, 'length', {
      value: entries.length,
      writable: false,
      configurable: false,
      enumerable: true,
    });
    arrayLike.item = function item(index) {
      return this[index] || null;
    };
    arrayLike.namedItem = function namedItem(name) {
      if (!keyProp) {
        return null;
      }
      return entries.find((entry) => entry && entry[keyProp] === name) || null;
    };
    arrayLike[Symbol.iterator] = function iterator() {
      let i = 0;
      return {
        next() {
          if (i < entries.length) {
            const value = entries[i];
            i += 1;
            return { value, done: false };
          }
          return { value: undefined, done: true };
        },
      };
    };
    arrayLike.refresh = function refresh() {};
    return Object.freeze(arrayLike);
  }

  function createPluginRecord(name, filename) {
    const plugin = {
      name,
      filename,
      description: `${name} plugin`,
    };
    Object.defineProperty(plugin, '__mimes', {
      value: [],
      writable: true,
      configurable: false,
      enumerable: false,
    });
    Object.defineProperty(plugin, 'length', {
      get() {
        return plugin.__mimes.length;
      },
      enumerable: true,
    });
    plugin.item = function item(index) {
      return plugin.__mimes[index] || null;
    };
    plugin.namedItem = function namedItem(type) {
      return plugin.__mimes.find((mime) => mime.type === type) || null;
    };
    plugin[Symbol.iterator] = function iterator() {
      let i = 0;
      return {
        next() {
          if (i < plugin.__mimes.length) {
            const value = plugin.__mimes[i];
            i += 1;
            return { value, done: false };
          }
          return { value: undefined, done: true };
        },
      };
    };
    plugin.refresh = function refresh() {};
    return plugin;
  }

  function createMimeRecord(type, plugin) {
    return {
      type,
      description: type,
      suffixes: '',
      enabledPlugin: plugin || null,
    };
  }

  const surfaceCache = new Map();

  function memoizeSurface(name, key, factory) {
    const cacheKey = `${name}::${key}`;
    if (!surfaceCache.has(cacheKey)) {
      surfaceCache.set(cacheKey, factory());
    }
    return surfaceCache.get(cacheKey);
  }

  function buildPluginCollections(config) {
    if (!config.enable_plugin_spoof) {
      return { plugins: null, mimeTypes: null };
    }
    const pluginNames = coerceList(config.plugins);
    const mimeNames = coerceList(config.mime_types);
    if (!pluginNames.length && !mimeNames.length) {
      return { plugins: null, mimeTypes: null };
    }
    const pluginRecords = (pluginNames.length ? pluginNames : ['Static Plugin']).map((name, idx) => createPluginRecord(name || `Plugin ${idx + 1}`, `plugin${idx}.dll`));
    const mimeRecords = mimeNames.map((type, idx) => {
      const plugin = pluginRecords[idx % pluginRecords.length];
      const mime = createMimeRecord(type, plugin);
      plugin.__mimes.push(mime);
      return mime;
    });
    pluginRecords.forEach((plugin) => {
      Object.freeze(plugin.__mimes);
      Object.freeze(plugin);
    });
    mimeRecords.forEach((mime) => Object.freeze(mime));
    const pluginArray = createArrayLike(pluginRecords, 'name');
    const mimeArray = createArrayLike(mimeRecords, 'type');
    return {
      plugins: pluginArray,
      mimeTypes: mimeArray,
    };
  }

  function getPluginCollectionsForConfig(config) {
    const key = JSON.stringify({
      enable: Boolean(config.enable_plugin_spoof),
      plugins: config.plugins || null,
      mime: config.mime_types || null,
    });
    return memoizeSurface('pluginCollections', key, () => buildPluginCollections(config));
  }

  function getConnectionForConfig(config, original) {
    const key = JSON.stringify({
      downlink: config.network_downlink,
      rtt: config.network_rtt,
      effectiveType: config.network_effective_type,
      saveData: config.network_save_data,
    });
    return memoizeSurface('connection', key, () => buildConnectionProxy(config, original));
  }

  function getMediaCapabilitiesForConfig(config, original) {
    const key = JSON.stringify({
      media: config.media_capabilities || null,
    });
    return memoizeSurface('mediaCapabilities', key, () => buildMediaCapabilities(config, original));
  }

  function getGpuProxy(config) {
    const key = JSON.stringify({
      renderer: config.webgl_renderer,
      vendor: config.webgl_vendor,
      enable: config.enable_webgl_spoof,
    });
    return memoizeSurface('gpu', key, () => buildGpuProxy(config));
  }

  function getGeolocationProxy() {
    return memoizeSurface('geolocation', 'global', () => buildGeolocationProxy());
  }

  function getStorageProxy(config, original) {
    const key = JSON.stringify({
      quota: config.storage_quota,
      usage: config.storage_usage,
      persisted: config.storage_persisted,
    });
    return memoizeSurface('storage', key, () => buildStorageProxy(config, original));
  }

  function getStorageBucketsProxy(config) {
    const key = JSON.stringify({ bucketQuota: config.storage_bucket_quota });
    return memoizeSurface('storageBuckets', key, () => buildStorageBuckets(config));
  }

  function getBatteryManager() {
    return memoizeSurface('battery', 'global', () => createBatteryManager());
  }

  function buildConnectionProxy(config, original) {
    const downlink = Number(config.network_downlink) || 10;
    const rtt = Number(config.network_rtt) || 50;
    const effectiveType = config.network_effective_type || '4g';
    const saveData = Boolean(config.network_save_data);
    const listeners = new Set();
    const proxy = {
      get downlink() { return downlink; },
      get downlinkMax() { return downlink; },
      get effectiveType() { return effectiveType; },
      get rtt() { return rtt; },
      get saveData() { return saveData; },
      onchange: null,
      addEventListener(type, handler) {
        if (type === 'change' && typeof handler === 'function') {
          listeners.add(handler);
        }
      },
      removeEventListener(type, handler) {
        if (type === 'change') {
          listeners.delete(handler);
        }
      },
      dispatchEvent(event) {
        if (event && event.type === 'change') {
          listeners.forEach((listener) => {
            try { listener.call(proxy, event); } catch (err) { /* swallow */ }
          });
          if (typeof proxy.onchange === 'function') {
            try { proxy.onchange.call(proxy, event); } catch (err) { /* swallow */ }
          }
        }
        return true;
      },
    };
    return original ? Object.setPrototypeOf(proxy, original) : proxy;
  }

  function buildMediaCapabilities(config, original) {
    const defaults = (config.media_capabilities && config.media_capabilities.decoding) || {};
    const proxy = {
      decodingInfo(configuration) {
        const key = configuration && configuration.video ? configuration.video.contentType : 'default';
        const overrides = defaults[key] || defaults.default || {};
        const result = {
          supported: overrides.supported !== undefined ? overrides.supported : true,
          powerEfficient: overrides.powerEfficient !== undefined ? overrides.powerEfficient : true,
          smooth: overrides.smooth !== undefined ? overrides.smooth : true,
          configuration: configuration || null,
        };
        return Promise.resolve(result);
      },
    };
    if (original) {
      return Object.setPrototypeOf(proxy, original);
    }
    return proxy;
  }

  function buildGpuProxy(config) {
    if (!config.enable_webgl_spoof && !config.webgl_renderer) {
      return undefined;
    }
    const adapterInfo = {
      name: config.webgl_renderer || 'ANGLE (NVIDIA GeForce GTX 1660 Ti)',
      vendor: config.webgl_vendor || 'Google Inc. (NVIDIA)',
      architecture: 'unknown',
      device: 'static',
      description: config.webgl_renderer || 'Static Renderer',
    };
    function buildAdapter() {
      return {
        info: adapterInfo,
        isFallbackAdapter: false,
        features: new Set(),
        limits: { maxTextureDimension2D: 16384 },
        requestDevice() {
          return Promise.resolve({ queue: { submit() {} } });
        },
      };
    }
    return {
      requestAdapter() {
        return Promise.resolve(buildAdapter());
      },
    };
  }

  function buildGeolocationProxy() {
    const PermissionError = {
      code: 1,
      message: 'User denied Geolocation',
      PERMISSION_DENIED: 1,
      POSITION_UNAVAILABLE: 2,
      TIMEOUT: 3,
    };
    let watchId = 0;
    const watchers = new Map();
    function invokeError(cb) {
      if (typeof cb === 'function') {
        setTimeout(() => cb(Object.assign({}, PermissionError)), 0);
      }
    }
    return {
      getCurrentPosition(success, error) {
        invokeError(error);
      },
      watchPosition(success, error) {
        const id = watchId + 1;
        watchId = id;
        watchers.set(id, { success, error });
        invokeError(error);
        return id;
      },
      clearWatch(id) {
        watchers.delete(id);
      },
    };
  }

  function clampTimestamp(value, base) {
    if (!Number.isFinite(value)) {
      return base;
    }
    return Math.round(value * 10) / 10;
  }

  function buildPerformanceProxy(nativePerformance) {
    const base = nativePerformance || {};
    const navigationStart = (base.timing && base.timing.navigationStart) || Date.now();
    const perfNoise = createPRNG('perf');
    function sanitizeEntry(entry) {
      if (!entry || typeof entry !== 'object') {
        return entry;
      }
      const clone = Object.assign({}, entry);
      if (typeof clone.startTime === 'number') {
        clone.startTime = clampTimestamp(clone.startTime, navigationStart);
      }
      if (typeof clone.duration === 'number') {
        clone.duration = clampTimestamp(clone.duration, 0);
      }
      return clone;
    }
    const timingProxy = base.timing ? new Proxy(base.timing, {
      get(target, prop) {
        const value = target[prop];
        if (typeof value === 'number') {
          return clampTimestamp(value, navigationStart);
        }
        if (typeof value === 'function') {
          return value.bind(target);
        }
        return value;
      },
    }) : undefined;

    return new Proxy(base, {
      get(target, prop) {
        if (prop === 'now') {
          const original = target.now ? target.now.bind(target) : Date.now;
          return function spoofedNow() {
            const real = original();
            const jitter = (perfNoise() - 0.5) * 0.3;
            return clampTimestamp(real + jitter, navigationStart);
          };
        }
        if (prop === 'timeOrigin') {
          return clampTimestamp(target.timeOrigin || navigationStart, navigationStart);
        }
        if (prop === 'timing') {
          return timingProxy;
        }
        if (prop === 'getEntriesByType') {
          return function getEntriesByType(type) {
            const entries = target.getEntriesByType ? target.getEntriesByType(type) : [];
            return entries.map(sanitizeEntry);
          };
        }
        if (prop === 'getEntries') {
          return function getEntries() {
            const entries = target.getEntries ? target.getEntries() : [];
            return entries.map(sanitizeEntry);
          };
        }
        if (prop === 'getEntriesByName') {
          return function getEntriesByName(name, type) {
            const entries = target.getEntriesByName ? target.getEntriesByName(name, type) : [];
            return entries.map(sanitizeEntry);
          };
        }
        const value = Reflect.get(target, prop, target);
        if (typeof value === 'function') {
          return value.bind(target);
        }
        return value;
      },
    });
  }

  function installPerformanceObserverShim() {
    if (typeof window.PerformanceObserver !== 'function') {
      return;
    }
    const OriginalObserver = window.PerformanceObserver;
    function WrappedObserver(callback) {
      const wrapped = function wrapped(list, observer) {
        const entries = list.getEntries().map((entry) => ({
          name: entry.name,
          entryType: entry.entryType,
          startTime: clampTimestamp(entry.startTime, 0),
          duration: clampTimestamp(entry.duration, 0),
          toJSON: entry.toJSON ? entry.toJSON.bind(entry) : undefined,
        }));
        const proxyList = {
          getEntries: () => entries,
          getEntriesByType: (type) => entries.filter((entry) => entry.entryType === type),
          getEntriesByName: (name, type) => entries.filter((entry) => entry.name === name && (!type || entry.entryType === type)),
          [Symbol.iterator]: function iterator() {
            let i = 0;
            return {
              next() {
                if (i < entries.length) {
                  const value = entries[i];
                  i += 1;
                  return { value, done: false };
                }
                return { value: undefined, done: true };
              },
            };
          },
        };
        callback(proxyList, observer);
      };
      return new OriginalObserver(wrapped);
    }
    WrappedObserver.prototype = OriginalObserver.prototype;
    WrappedObserver.prototype.constructor = WrappedObserver;
    WrappedObserver.supportedEntryTypes = (OriginalObserver.supportedEntryTypes || []).slice();
    window.PerformanceObserver = WrappedObserver;
  }

  function buildStorageProxy(config, original) {
    const quota = Number(config.storage_quota) || 107374182400;
    const usage = Number.isFinite(config.storage_usage) ? Number(config.storage_usage) : Math.floor(quota * 0.12);
    const persisted = Boolean(config.storage_persisted);
    const proxy = {
      estimate() {
        return Promise.resolve({ quota, usage });
      },
      persisted() {
        return Promise.resolve(persisted);
      },
    };
    if (original) {
      const clone = Object.create(Object.getPrototypeOf(original) || Object.prototype);
      return Object.assign(clone, original, proxy);
    }
    return proxy;
  }

  function buildStorageBuckets(config) {
    return {
      open(name) {
        const bucket = {
          name: name || 'default',
          persisted: false,
          quota: Number(config.storage_bucket_quota) || 5368709120,
        };
        return Promise.resolve(bucket);
      },
      keys() {
        return Promise.resolve(['default']);
      },
      delete() {
        return Promise.resolve(false);
      },
    };
  }

  function createBatteryManager() {
    const listeners = new Map();
    const battery = {
      charging: true,
      chargingTime: 0,
      dischargingTime: Infinity,
      level: 1,
      addEventListener(type, handler) {
        if (!listeners.has(type)) {
          listeners.set(type, new Set());
        }
        if (typeof handler === 'function') {
          listeners.get(type).add(handler);
        }
      },
      removeEventListener(type, handler) {
        if (listeners.has(type)) {
          listeners.get(type).delete(handler);
        }
      },
      dispatchEvent(event) {
        const bucket = listeners.get(event && event.type);
        if (bucket) {
          bucket.forEach((handler) => {
            try { handler.call(battery, event); } catch (err) { /* swallow */ }
          });
        }
        return true;
      },
    };
    Object.defineProperties(battery, {
      onchargingchange: {
        set(handler) {
          battery.addEventListener('chargingchange', handler);
        },
      },
      onlevelchange: {
        set(handler) {
          battery.addEventListener('levelchange', handler);
        },
      },
      ondischargingtimechange: {
        set(handler) {
          battery.addEventListener('dischargingtimechange', handler);
        },
      },
    });
    return battery;
  }

  function createPermissionStatus(name, state) {
    const listeners = new Set();
    return {
      name,
      state,
      onchange: null,
      addEventListener(type, handler) {
        if (type === 'change' && typeof handler === 'function') {
          listeners.add(handler);
        }
      },
      removeEventListener(type, handler) {
        if (type === 'change') {
          listeners.delete(handler);
        }
      },
      dispatchEvent(event) {
        if (event && event.type === 'change') {
          listeners.forEach((handler) => {
            try { handler.call(this, event); } catch (err) { /* swallow */ }
          });
          if (typeof this.onchange === 'function') {
            try { this.onchange.call(this, event); } catch (err) { /* swallow */ }
          }
        }
        return true;
      },
    };
  }

  function installNotificationGuards() {
    const NativeNotification = native.Notification;
    function StaticNotification() {
      throw createDomException('Notifications denied by STATIC profile', 'NotAllowedError');
    }
    Object.defineProperty(StaticNotification, 'permission', {
      configurable: true,
      enumerable: true,
      get() {
        return 'denied';
      },
    });
    StaticNotification.requestPermission = function requestPermission(callback) {
      const response = Promise.resolve('denied');
      if (typeof callback === 'function') {
        response.then((result) => callback(result));
      }
      return response;
    };
    if (NativeNotification && NativeNotification.prototype) {
      StaticNotification.prototype = NativeNotification.prototype;
    }
    window.Notification = StaticNotification;
  }

  function buildUAData(config) {
    const browserType = config.browser_type || config.browserType || 'chrome';
    if (browserType === 'firefox') {
      return undefined;
    }

    const brands = [];
    if (config.sec_ch_ua) {
      const matcher = config.sec_ch_ua.matchAll(/"([^"]+)";v="([^"]+)"/g);
      for (const match of matcher) {
        brands.push({ brand: match[1], version: match[2] });
      }
    }
    if (!brands.length) {
      brands.push({ brand: 'Not?A_Brand', version: '8' });
      brands.push({ brand: 'Chromium', version: '112' });
    }

    const uaVersion = (function deriveVersion() {
      const ua = config.user_agent || native.navigator.userAgent || '';
      const match = ua.match(/Chrome\/([0-9.]+)/);
      if (match && match[1]) {
        return match[1];
      }
      return '112.0.0.0';
    })();

    const fullVersionList = brands.map((entry) => ({
      brand: entry.brand,
      version: entry.brand === 'Not?A_Brand' ? '8.0.0.0' : uaVersion,
    }));

    return Object.freeze({
      brands: freezeList(brands),
      mobile: config.sec_ch_ua_mobile === '?1',
      platform: (config.sec_ch_ua_platform || config.platform || 'Windows').replace(/"/g, ''),
      getHighEntropyValues(hints) {
        const values = {
          brands: this.brands,
          mobile: this.mobile,
          platform: this.platform,
          platformVersion: (config.sec_ch_ua_platform_version || '15.0.0').replace(/"/g, ''),
          architecture: (config.sec_ch_ua_arch || 'x86').replace(/"/g, ''),
          bitness: (config.sec_ch_ua_bitness || '64').replace(/"/g, ''),
          model: '',
          uaFullVersion: uaVersion,
          fullVersionList: freezeList(fullVersionList),
          wow64: false,
          formFactors: freezeList(['Desktop']),
        };

        if (Array.isArray(hints) && hints.length) {
          const filtered = {};
          hints.forEach((hint) => {
            if (Object.prototype.hasOwnProperty.call(values, hint)) {
              filtered[hint] = values[hint];
            }
          });
          return Promise.resolve(filtered);
        }
        return Promise.resolve(values);
      },
      toJSON() {
        return {
          brands: this.brands,
          mobile: this.mobile,
          platform: this.platform,
        };
      },
    });
  }

  function buildMediaDevices(config, original) {
    const devices = Array.isArray(config.media_devices)
      ? config.media_devices
      : [];
    const proxy = {
      enumerateDevices() {
        const synthesized = devices.map((descriptor, idx) => ({
          deviceId: descriptor.deviceId || `static-device-${idx}`,
          groupId: descriptor.groupId || 'static-group',
          kind: descriptor.kind || 'audioinput',
          label: descriptor.label || 'Static Device',
          toJSON() {
            return {
              deviceId: this.deviceId,
              groupId: this.groupId,
              kind: this.kind,
              label: this.label,
            };
          },
        }));
        return Promise.resolve(synthesized);
      },
      getUserMedia() {
        return Promise.reject(createDomException('Permissions denied by policy', 'NotAllowedError'));
      },
      addEventListener() {},
      removeEventListener() {},
    };
    if (original && typeof original.getSupportedConstraints === 'function') {
      proxy.getSupportedConstraints = original.getSupportedConstraints.bind(original);
    }
    if (original && typeof original.addEventListener === 'function') {
      proxy.addEventListener = original.addEventListener.bind(original);
      proxy.removeEventListener = original.removeEventListener.bind(original);
    }
    return proxy;
  }

  const navigatorProxy = new Proxy(native.navigator, {
    has(target, prop) {
      if (prop === 'vendorFlavors') {
        const config = getConfig();
        const browserType = config.browser_type || config.browserType || 'chrome';
        return resolveVendorFlavors(config, browserType) !== null;
      }
      return prop in target;
    },
    get(target, prop, receiver) {
      const config = getConfig();
      const browserType = config.browser_type || config.browserType || 'chrome';

      switch (prop) {
        case 'userAgent':
          return config.user_agent || target.userAgent;
        case 'platform':
          return config.platform || target.platform;
        case 'vendor':
          return resolveVendorValue(config, browserType);
        case 'vendorSub':
          return '';
        case 'productSub':
          return browserType === 'firefox' ? '20100101' : '20030107';
        case 'product':
          return 'Gecko';
        case 'hardwareConcurrency':
          return config.hardware_concurrency || target.hardwareConcurrency;
        case 'deviceMemory':
          return normalizeDeviceMemory(config.device_memory || target.deviceMemory);
        case 'maxTouchPoints':
          return typeof config.max_touch_points === 'number' ? config.max_touch_points : (target.maxTouchPoints || 0);
        case 'languages':
          return normalizeLangs(config);
        case 'language':
          return normalizeLangs(config)[0];
        case 'doNotTrack':
          return config.do_not_track !== undefined ? config.do_not_track : target.doNotTrack;
        case 'cookieEnabled':
          return config.cookie_enabled !== undefined ? config.cookie_enabled : target.cookieEnabled;
        case 'webdriver':
          return false;
        case 'appVersion': {
          if (!config.user_agent) {
            return target.appVersion;
          }
          if (config.user_agent.includes('Firefox/')) {
            if (config.platform && config.platform.includes('Linux')) {
              return '5.0 (X11)';
            }
            if (config.platform && config.platform.includes('Mac')) {
              return '5.0 (Macintosh)';
            }
            return '5.0 (Windows)';
          }
          return config.user_agent.split('Mozilla/')[1] || target.appVersion;
        }
        case 'appName':
          return 'Netscape';
        case 'appCodeName':
          return 'Mozilla';
        case 'oscpu':
          if (browserType === 'firefox') {
            if (config.platform === 'Win32') {
              return 'Windows NT 10.0; Win64; x64';
            }
            return config.platform || 'Linux x86_64';
          }
          return undefined;
        case 'buildID':
          return browserType === 'firefox' ? '20181001000000' : undefined;
        case 'userAgentData':
          return buildUAData(config);
        case 'vendorFlavors': {
          const flavors = resolveVendorFlavors(config, browserType);
          if (flavors === null) {
            return undefined;
          }
          return flavors;
        }
        case 'plugins': {
          const collections = getPluginCollectionsForConfig(config);
          return collections.plugins || target.plugins;
        }
        case 'mimeTypes': {
          const collections = getPluginCollectionsForConfig(config);
          return collections.mimeTypes || target.mimeTypes;
        }
        case 'pdfViewerEnabled':
          return browserType === 'firefox' ? false : true;
        case 'permissions':
          if (browserType === 'firefox') {
            return target.permissions;
          }
          return {
            query(desc) {
              const name = (desc && desc.name) || '';
              const deniedPermissions = new Set(['notifications', 'push', 'geolocation', 'camera', 'microphone', 'background-sync']);
              const state = deniedPermissions.has(name) ? 'denied' : 'prompt';
              return Promise.resolve(createPermissionStatus(name, state));
            },
          };
        case 'geolocation':
          return getGeolocationProxy();
        case 'getBattery':
          return function getBattery() {
            return Promise.resolve(getBatteryManager());
          };
        case Symbol.hasInstance:
        case 'hasOwnProperty': {
          const fn = Reflect.get(target, prop, target);
          if (typeof fn === 'function') {
            return function patchedCheck() {
              if (arguments[0] === 'vendorFlavors' && resolveVendorFlavors(config, browserType) === null) {
                return false;
              }
              return Reflect.apply(fn, target, arguments);
            };
          }
          return fn;
        }
        case 'bluetooth':
          if (browserType === 'firefox') {
            return target.bluetooth;
          }
          return {
            requestDevice() {
              return Promise.reject(createDomException('Bluetooth adapter not available', 'NotFoundError'));
            },
            getAvailability() {
              return Promise.resolve(false);
            },
          };
        case 'usb':
          if (browserType === 'firefox') {
            return target.usb;
          }
          return {
            requestDevice() {
              return Promise.reject(createDomException('No device selected', 'NotFoundError'));
            },
            getDevices() {
              return Promise.resolve([]);
            },
          };
        case 'mediaDevices':
          if (!config.media_devices) {
            return target.mediaDevices;
          }
          return buildMediaDevices(config, target.mediaDevices || null);
        case 'connection':
          if (browserType === 'firefox') {
            return target.connection;
          }
          return getConnectionForConfig(config, target.connection || null);
        case 'mediaCapabilities':
          if (browserType === 'firefox') {
            return target.mediaCapabilities;
          }
          return getMediaCapabilitiesForConfig(config, target.mediaCapabilities || null);
        case 'gpu': {
          if (browserType === 'firefox') {
            return target.gpu;
          }
          const gpuProxy = getGpuProxy(config);
          return gpuProxy || target.gpu;
        }
        case 'webkitTemporaryStorage':
          if (browserType === 'firefox') {
            return undefined;
          }
          return {
            queryUsageAndQuota(cb) {
              if (typeof cb === 'function') {
                setTimeout(() => {
                  const quota = config.storage_quota || 107374182400;
                  cb(Math.floor(quota * 0.1), quota);
                }, 0);
              }
            },
          };
        case 'storage':
          if (config.enable_storage_spoof === false) {
            return target.storage;
          }
          return getStorageProxy(config, target.storage || null);
        case 'storageBuckets':
          if (browserType === 'firefox') {
            return undefined;
          }
          return getStorageBucketsProxy(config);
        default:
          break;
      }

      const value = Reflect.get(target, prop, target);
      if (typeof value === 'function') {
        return value.bind(target);
      }
      return value;
    },
    ownKeys(target) {
      const keys = Reflect.ownKeys(target);
      const config = getConfig();
      const browserType = config.browser_type || config.browserType || 'chrome';
      if (resolveVendorFlavors(config, browserType) === null) {
        return keys.filter((key) => key !== 'vendorFlavors');
      }
      return keys;
    },
  });

  const screenProxy = new Proxy(native.screen || {}, {
    get(target, prop, receiver) {
      const config = getConfig();
      if (config.screen_resolution) {
        const parts = String(config.screen_resolution).split('x').map((value) => parseInt(value, 10));
        const width = parts[0];
        const height = parts[1];
        if (prop === 'width') return width;
        if (prop === 'height') return height;
        if (prop === 'availWidth') return config.screen_avail_width || width;
        if (prop === 'availHeight') return config.screen_avail_height || (height - 40);
        if (prop === 'availTop') return config.screen_avail_top || 0;
        if (prop === 'availLeft') return config.screen_avail_left || 0;
      }

      if ((prop === 'colorDepth' || prop === 'pixelDepth') && config.color_depth) {
        return config.color_depth;
      }

      if (prop === 'orientation') {
        return {
          type: config.screen_orientation_type || 'landscape-primary',
          angle: config.screen_orientation_angle || 0,
          onchange: null,
        };
      }

      if (prop === 'isExtended') {
        return config.screen_is_extended || false;
      }

      const value = Reflect.get(target, prop, target);
      if (typeof value === 'function') {
        return value.bind(target);
      }
      return value;
    },
  });

  const performanceProxy = buildPerformanceProxy(native.performance || {});
  installPerformanceObserverShim();

  function formatOffsetString(offsetMinutes) {
    const actual = -offsetMinutes;
    const sign = actual >= 0 ? '+' : '-';
    const absolute = Math.abs(actual);
    const hours = String(Math.floor(absolute / 60)).padStart(2, '0');
    const minutes = String(absolute % 60).padStart(2, '0');
    return `${sign}${hours}${minutes}`;
  }

  function computeTimezoneOffset(date, timeZone) {
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        hour12: false,
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
      const parts = formatter.formatToParts(date).reduce((acc, part) => {
        acc[part.type] = part.value;
        return acc;
      }, {});
      const asUTC = Date.UTC(
        Number(parts.year),
        Number(parts.month) - 1,
        Number(parts.day),
        Number(parts.hour),
        Number(parts.minute),
        Number(parts.second)
      );
      return -(asUTC - date.getTime()) / 60000;
    } catch (err) {
      return date.getTimezoneOffset();
    }
  }

  const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function patchedOffset() {
    const tz = getConfig().timezone;
    if (!tz) {
      return originalGetTimezoneOffset.call(this);
    }
    return computeTimezoneOffset(this, tz);
  };

  const originalToString = Date.prototype.toString;
  Date.prototype.toString = function patchedToString() {
    const tz = getConfig().timezone;
    if (!tz) {
      return originalToString.call(this);
    }
    const offsetMinutes = this.getTimezoneOffset();
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        weekday: 'short',
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZoneName: 'short',
      });
      const parts = formatter.formatToParts(this).reduce((acc, part) => {
        acc[part.type] = part.value;
        return acc;
      }, {});
      return `${parts.weekday} ${parts.month} ${parts.day} ${parts.year} ${parts.hour}:${parts.minute}:${parts.second} GMT${formatOffsetString(offsetMinutes)} (${parts.timeZoneName})`;
    } catch (err) {
      return originalToString.call(this);
    }
  };

  const originalToTimeString = Date.prototype.toTimeString;
  Date.prototype.toTimeString = function patchedToTimeString() {
    const tz = getConfig().timezone;
    if (!tz) {
      return originalToTimeString.call(this);
    }
    const offsetMinutes = this.getTimezoneOffset();
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZoneName: 'short',
      });
      const parts = formatter.formatToParts(this).reduce((acc, part) => {
        acc[part.type] = part.value;
        return acc;
      }, {});
      return `${parts.hour}:${parts.minute}:${parts.second} GMT${formatOffsetString(offsetMinutes)} (${parts.timeZoneName})`;
    } catch (err) {
      return originalToTimeString.call(this);
    }
  };

  const originalToLocaleString = Date.prototype.toLocaleString;
  Date.prototype.toLocaleString = function patchedLocaleString(locales, options) {
    const tz = getConfig().timezone;
    if (!tz) {
      return originalToLocaleString.call(this, locales, options);
    }
    const merged = Object.assign({ timeZone: tz }, options || {});
    return originalToLocaleString.call(this, locales, merged);
  };

  if (window.Intl && window.Intl.DateTimeFormat) {
    const OriginalDateTimeFormat = window.Intl.DateTimeFormat;
    function PatchedDateTimeFormat(locales, options) {
      const config = getConfig();
      const appliedOptions = Object.assign({}, options || {});
      if (!appliedOptions.timeZone && config.timezone) {
        appliedOptions.timeZone = config.timezone;
      }
      return new OriginalDateTimeFormat(locales, appliedOptions);
    }
    PatchedDateTimeFormat.prototype = OriginalDateTimeFormat.prototype;
    PatchedDateTimeFormat.prototype.constructor = PatchedDateTimeFormat;
    PatchedDateTimeFormat.supportedLocalesOf = OriginalDateTimeFormat.supportedLocalesOf.bind(OriginalDateTimeFormat);
    window.Intl.DateTimeFormat = PatchedDateTimeFormat;
  }

  (function installMeasurementNoise() {
    const width = native.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    const height = native.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
    if (!width || !height) {
      return;
    }

    function applyNoise(element, base) {
      const config = getConfig();
      if (!config || config.enable_dom_measurement_noise !== true) {
        return base;
      }
      const signature = `${element && element.tagName ? element.tagName : 'node'}::${element && element.className ? element.className : ''}::${base}`;
      const hash = window.__static_hash(signature + getSessionEntropy());
      const delta = (parseInt(hash.slice(0, 2), 16) % 3) - 1; // -1, 0, or +1 pixels
      return base + delta;
    }

    native.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      configurable: true,
      get() {
        const base = width.get.call(this);
        return applyNoise(this, base);
      },
    });

    native.defineProperty(HTMLElement.prototype, 'offsetHeight', {
      configurable: true,
      get() {
        const base = height.get.call(this);
        return applyNoise(this, base);
      },
    });
  }());

  function defineGlobal(target, key, value) {
    try {
      native.defineProperty(target, key, {
        value,
        writable: false,
        configurable: false,
        enumerable: true,
      });
      return true;
    } catch (err) {
      try {
        target[key] = value;
        return true;
      } catch (err2) {
        console.warn(LOG, 'failed to set', key, err2.message);
        return false;
      }
    }
  }

  function cloneDescriptor(descriptor) {
    if (!descriptor) {
      return null;
    }
    const clone = {};
    if ('configurable' in descriptor) clone.configurable = descriptor.configurable;
    if ('enumerable' in descriptor) clone.enumerable = descriptor.enumerable;
    if ('writable' in descriptor) clone.writable = descriptor.writable;
    if ('get' in descriptor) clone.get = descriptor.get;
    if ('set' in descriptor) clone.set = descriptor.set;
    if ('value' in descriptor) clone.value = descriptor.value;
    return clone;
  }

  function installGlobalProperty(target, key, value) {
    const descriptor = cloneDescriptor(originalDescriptors[key]);
    if (descriptor) {
      if (typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
        descriptor.get = () => value;
        descriptor.set = undefined;
      } else {
        descriptor.value = value;
      }
      try {
        native.defineProperty(target, key, descriptor);
        return true;
      } catch (err) {
        console.warn(LOG, 'descriptor install failed for', key, err.message);
      }
    }
    return defineGlobal(target, key, value);
  }

  function defineGetter(target, key, getter) {
    const descriptor = cloneDescriptor(originalDescriptors[key]) || {};
    descriptor.get = getter;
    descriptor.set = undefined;
    if (!('configurable' in descriptor)) descriptor.configurable = true;
    if (!('enumerable' in descriptor)) descriptor.enumerable = true;
    try {
      native.defineProperty(target, key, descriptor);
      return true;
    } catch (err) {
      try {
        target[key] = getter();
        return true;
      } catch (err2) {
        console.warn(LOG, 'failed to set getter', key, err2.message);
        return false;
      }
    }
  }

  installGlobalProperty(window, 'navigator', navigatorProxy);
  installGlobalProperty(window, 'screen', screenProxy);
  installGlobalProperty(window, 'performance', performanceProxy);

  const config = getConfig();
  const viewport = deriveViewportMetrics(config);
  defineGetter(window, 'devicePixelRatio', () => viewport.devicePixelRatio);
  defineGetter(window, 'innerWidth', () => viewport.innerWidth);
  defineGetter(window, 'innerHeight', () => viewport.innerHeight);
  defineGetter(window, 'outerWidth', () => viewport.outerWidth);
  defineGetter(window, 'outerHeight', () => viewport.outerHeight);

  installNotificationGuards();

  const spoofedGlobals = {
    navigator: navigatorProxy,
    screen: screenProxy,
    performance: performanceProxy,
  };

  try {
    native.defineProperty(window, '__static_spoofed_globals', {
      value: spoofedGlobals,
      writable: false,
      configurable: false,
      enumerable: false,
    });
  } catch (err) {
    window.__static_spoofed_globals = spoofedGlobals;
  }

  if (!window.__404_spoofed_globals) {
    window.__404_spoofed_globals = spoofedGlobals;
  }

  window.__404_shim_active = true;
  window.__static_shim_active = true;
  window.__404_shim_version = '2.1.0';
  window.__static_shim_version = '2.1.0';
  window[MARK] = true;

  console.log(LOG, 'globals spoofed');
})();
