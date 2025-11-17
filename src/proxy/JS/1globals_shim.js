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

(function createGlobalsShim() {
  'use strict';
  
  if (window.__404_spoofed_globals) {
    console.warn('[404] Globals already created');
    return;
  }

  if (!window.__404_bootstrap_active) {
    console.error('[404] CRITICAL: Bootstrap missing!');
    console.error('[404] Continuing with degraded protection...');
  }

  function getConfig() {
    return window.__fpConfig || {};
  }

  function createPRNG(seed) {
    const config = getConfig();
    const randomEntropy = window.__404_session_id || Math.random().toString(36);
    const fullSeed = (config.name || 'default') + (seed || 'default_seed') + randomEntropy;

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

  const originalNavigator = window.navigator;

  const navigatorProxy = new Proxy(originalNavigator, {
    get(target, prop, receiver) {
      const config = getConfig();

      if (prop === 'userAgent' && config.user_agent) {
        return config.user_agent;
      }
      if (prop === 'platform' && config.platform) {
        return config.platform;
      }
      if (prop === 'vendor') {
        const browserType = config.browser_type || 'chrome';
        return browserType === 'firefox' ? '' : 'Google Inc.';
      }
      if (prop === 'vendorSub') {
        return '';
      }
      if (prop === 'productSub') {
        const browserType = config.browser_type || 'chrome';
        return browserType === 'firefox' ? '20100101' : '20030107';
      }
      if (prop === 'product') {
        return 'Gecko';
      }

      if (prop === 'hardwareConcurrency' && config.hardware_concurrency) {
        return config.hardware_concurrency;
      }
      if (prop === 'deviceMemory' && config.device_memory) {
        return config.device_memory;
      }
      if (prop === 'maxTouchPoints') {
        return config.max_touch_points !== undefined ? config.max_touch_points : 0;
      }

      if (prop === 'language' && config.languages && config.languages[0]) {
        return config.languages[0];
      }
      if (prop === 'languages' && config.languages) {
        return Object.freeze(config.languages.slice());
      }

      if (prop === 'doNotTrack') {
        return config.do_not_track !== undefined ? config.do_not_track : null;
      }
      if (prop === 'cookieEnabled') {
        return config.cookie_enabled !== undefined ? config.cookie_enabled : true;
      }
      if (prop === 'webdriver') {
        return false; 
      }

      if (prop === 'appVersion') {
        if (config.user_agent) {
          if (config.user_agent.includes('Firefox/')) {
            if (config.platform === 'Win32') return '5.0 (Windows)';
            if (config.platform.includes('Linux')) return '5.0 (X11)';
            if (config.platform.includes('Mac')) return '5.0 (Macintosh)';
            return '5.0 (Windows)';
          } else {
            return config.user_agent.split('Mozilla/')[1] || '5.0';
          }
        }
      }
      if (prop === 'appName') {
        return 'Netscape';
      }
      if (prop === 'appCodeName') {
        return 'Mozilla';
      }

      if (prop === 'oscpu' && config.browser_type === 'firefox') {
        return config.platform === 'Win32' ? 'Windows NT 10.0; Win64; x64' : config.platform;
      }
      if (prop === 'buildID' && config.browser_type === 'firefox') {
        return '20181001000000';
      }

      if (prop === 'userAgentData') {
        const browserType = config.browser_type || 'chrome';

        if (browserType === 'firefox') {
          return undefined; 
        }

        const brands = [];
        if (config.sec_ch_ua) {
          const brandMatches = config.sec_ch_ua.matchAll(/"([^"]+)";v="([^"]+)"/g);
          for (const match of brandMatches) {
            brands.push({ brand: match[1], version: match[2] });
          }
        }

        const uaVersion = config.user_agent ? 
          (config.user_agent.match(/Chrome\/(\d+\.\d+\.\d+\.\d+)/)?.[1] || '108.0.0.0') : 
          '108.0.0.0';

        const fullVersionList = (brands.length > 0 ? brands : [
          { brand: "Not?A_Brand", version: "8" },
          { brand: "Chromium", version: "108" }
        ]).map(b => ({
          brand: b.brand,
          version: b.brand === "Not?A_Brand" ? "8.0.0.0" : uaVersion
        }));

        return Object.freeze({
          brands: Object.freeze((brands.length > 0 ? brands : [
            { brand: "Not?A_Brand", version: "8" },
            { brand: "Chromium", version: "108" }
          ]).slice()),
          mobile: config.sec_ch_ua_mobile === "?1",
          platform: config.sec_ch_ua_platform?.replace(/"/g, '') || config.platform,
          getHighEntropyValues: function(hints) {
            const values = {
              brands: this.brands,
              mobile: this.mobile,
              platform: this.platform,
              platformVersion: config.sec_ch_ua_platform_version?.replace(/"/g, '') || "15.0.0",
              architecture: config.sec_ch_ua_arch?.replace(/"/g, '') || "x86",
              bitness: config.sec_ch_ua_bitness?.replace(/"/g, '') || "64",
              model: "",
              uaFullVersion: uaVersion,
              fullVersionList: Object.freeze(fullVersionList.slice()),
              wow64: false,
              formFactors: Object.freeze(["Desktop"])
            };

            if (Array.isArray(hints) && hints.length > 0) {
              const filtered = {};
              hints.forEach(hint => {
                if (hint in values) filtered[hint] = values[hint];
              });
              return Promise.resolve(filtered);
            }

            return Promise.resolve(values);
          },
          toJSON: function() {
            return {
              brands: this.brands,
              mobile: this.mobile,
              platform: this.platform
            };
          }
        });
      }

      if (prop === 'vendorFlavors') {
        const browserType = config.browser_type || 'chrome';

        if (browserType === 'firefox') {
          return Object.freeze([]); 
        }

        return Object.freeze(['chrome']);
      }

      if (prop === 'plugins' && config.enable_plugin_spoof) {

        const pluginArray = [];
        if (config.plugins) {
          const pluginNames = config.plugins.split(',');
          pluginNames.forEach((name, idx) => {
            pluginArray.push({
              name: name.trim(),
              description: name.trim(),
              filename: `plugin${idx}.dll`,
              length: 0
            });
          });
        }
        pluginArray.item = function(index) { return this[index] || null; };
        pluginArray.namedItem = function(name) {
          return this.find(p => p.name === name) || null;
        };
        pluginArray.refresh = function() {};
        return Object.freeze(pluginArray);
      }

      if (prop === 'pdfViewerEnabled' && config.browser_type !== 'firefox') {
        return true;
      }

      if (prop === 'permissions' && config.browser_type !== 'firefox') {
        return {
          query: function(permissionDesc) {
            const permName = permissionDesc?.name || '';
            let state = 'prompt';
            if (permName === 'notifications') state = 'denied';
            return Promise.resolve({
              state: state,
              onchange: null,
              name: permName
            });
          }
        };
      }

      if (prop === 'geolocation' && config.enable_automation_evasion) {
        return {
          getCurrentPosition: function(success, error) {
            if (error) {
              setTimeout(() => error({
                code: 1,
                message: 'User denied Geolocation',
                PERMISSION_DENIED: 1,
                POSITION_UNAVAILABLE: 2,
                TIMEOUT: 3
              }), 0);
            }
          },
          watchPosition: function(success, error) {
            if (error) {
              setTimeout(() => error({
                code: 1,
                message: 'User denied Geolocation',
                PERMISSION_DENIED: 1,
                POSITION_UNAVAILABLE: 2,
                TIMEOUT: 3
              }), 0);
            }
            return 0;
          },
          clearWatch: function() {}
        };
      }

      if (prop === 'getBattery') {
        return function() {
          return Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 1.0,
            onchargingchange: null,
            onchargingtimechange: null,
            ondischargingtimechange: null,
            onlevelchange: null,
            addEventListener: function() {},
            removeEventListener: function() {},
            dispatchEvent: function() { return true; }
          });
        };
      }

      if (prop === 'bluetooth' && config.browser_type !== 'firefox') {
        return {
          requestDevice: function() {
            return Promise.reject(new DOMException('Bluetooth adapter not available', 'NotFoundError'));
          },
          getAvailability: function() {
            return Promise.resolve(false);
          }
        };
      }

      if (prop === 'usb' && config.browser_type !== 'firefox') {
        return {
          requestDevice: function() {
            return Promise.reject(new DOMException('No device selected', 'NotFoundError'));
          },
          getDevices: function() {
            return Promise.resolve([]);
          }
        };
      }

      if (prop === 'webkitTemporaryStorage' && config.browser_type !== 'firefox') {
        return {
          queryUsageAndQuota: function(successCallback) {
            setTimeout(() => {
              successCallback(
                Math.floor(config.storage_quota * 0.1) || 10737418240,
                config.storage_quota || 107374182400
              );
            }, 0);
          }
        };
      }

      const value = Reflect.get(target, prop, target);
      if (typeof value === 'function') {
        return value.bind(target);
      }
      return value;
    },

    ownKeys(target) {
      return Reflect.ownKeys(target);
    },

    has(target, prop) {
      return Reflect.has(target, prop);
    }
  });

  const originalScreen = window.screen;

  const screenProxy = new Proxy(originalScreen, {
    get(target, prop, receiver) {
      const config = getConfig();

      if (config.screen_resolution) {
        const [width, height] = config.screen_resolution.split('x').map(Number);

        if (prop === 'width') return width;
        if (prop === 'height') return height;
        if (prop === 'availWidth') return config.screen_avail_width || width;
        if (prop === 'availHeight') return config.screen_avail_height || (height - 40);
        if (prop === 'availTop') return config.screen_avail_top || 0;
        if (prop === 'availLeft') return config.screen_avail_left || 0;
      }

      if (prop === 'colorDepth' && config.color_depth) {
        return config.color_depth;
      }
      if (prop === 'pixelDepth' && config.color_depth) {
        return config.color_depth;
      }

      if (prop === 'orientation') {
        return {
          type: config.screen_orientation_type || 'landscape-primary',
          angle: config.screen_orientation_angle || 0,
          onchange: null
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
    }
  });

  const originalPerformance = window.performance;
  const performanceProxy = new Proxy(originalPerformance, {
    get(target, prop, receiver) {
      if (prop === 'now') {
        const originalNow = target.now.bind(target);
        return function now() {
          const real = originalNow();
          const jitter = (Math.random() - 0.5) * 0.2; 
          return real + jitter;
        };
      }

      const value = Reflect.get(target, prop, target);
      if (typeof value === 'function') {
        return value.bind(target);
      }
      return value;
    }
  });

  const config = getConfig();

  if (config.device_pixel_ratio !== undefined) {
    try {
      Object.defineProperty(window, 'devicePixelRatio', {
        get: function() {
          return config.device_pixel_ratio;
        },
        configurable: true
      });
      console.log('[404-SHIM] ✓ window.devicePixelRatio spoofed:', config.device_pixel_ratio);
    } catch (e) {
      console.warn('[404-SHIM] Could not spoof devicePixelRatio:', e.message);
    }
  }

  if (config.window_inner_width !== undefined && config.window_inner_height !== undefined) {
    try {
      Object.defineProperty(window, 'innerWidth', {
        get: function() {
          return config.window_inner_width;
        },
        configurable: true
      });
      Object.defineProperty(window, 'innerHeight', {
        get: function() {
          return config.window_inner_height;
        },
        configurable: true
      });
      console.log('[404-SHIM] ✓ window.innerWidth/innerHeight spoofed:', config.window_inner_width, 'x', config.window_inner_height);
    } catch (e) {
      console.warn('[404-SHIM] Could not spoof innerWidth/innerHeight:', e.message);
    }
  }

  if (config.window_outer_width !== undefined && config.window_outer_height !== undefined) {
    try {
      Object.defineProperty(window, 'outerWidth', {
        get: function() {
          return config.window_outer_width;
        },
        configurable: true
      });
      Object.defineProperty(window, 'outerHeight', {
        get: function() {
          return config.window_outer_height;
        },
        configurable: true
      });
      console.log('[404-SHIM] ✓ window.outerWidth/outerHeight spoofed:', config.window_outer_width, 'x', config.window_outer_height);
    } catch (e) {
      console.warn('[404-SHIM] Could not spoof outerWidth/outerHeight:', e.message);
    }
  }

  window.__404_spoofed_globals = {
    navigator: navigatorProxy,
    screen: screenProxy,
    performance: performanceProxy
  };

  try {
    Object.defineProperty(window, '__404_spoofed_globals', {
      value: window.__404_spoofed_globals,
      writable: false,
      enumerable: false,
      configurable: false
    });
    console.log('[404-SHIM] ✓ Spoofed globals stored for eval/Function contexts');
  } catch (e) {
    console.warn('[404-SHIM] Could not lock spoofed globals:', e.message);
  }

  try {

    Object.defineProperty(window, 'navigator', {
      value: navigatorProxy,
      writable: false,
      enumerable: true,
      configurable: false
    });
  } catch (e) {
    console.warn('[404] Navigator override failed:', e.message);

    try {
      window.navigator = navigatorProxy;
      console.log('[404-SHIM] ✓ window.navigator assigned via fallback');
    } catch (e2) {
      console.error('[404-SHIM] ✗ Failed to replace navigator:', e2.message);
    }
  }

  try {

    Object.defineProperty(window, 'screen', {
      value: screenProxy,
      writable: false,
      enumerable: true,
      configurable: false
    });
  } catch (e) {
    console.warn('[404] Screen override failed:', e.message);
    try {
      window.screen = screenProxy;
      console.log('[404-SHIM] ✓ window.screen assigned via fallback');
    } catch (e2) {
      console.error('[404-SHIM] ✗ Failed to replace screen:', e2.message);
    }
  }

  try {

    Object.defineProperty(window, 'performance', {
      value: performanceProxy,
      writable: false,
      enumerable: true,
      configurable: false
    });
  } catch (e) {
    console.warn('[404] Performance override failed:', e.message);
    try {
      window.performance = performanceProxy;
      console.log('[404-SHIM] ✓ window.performance assigned via fallback');
    } catch (e2) {
      console.error('[404-SHIM] ✗ Failed to replace performance:', e2.message);
    }
  }

  window.__404_shim_active = true;
  window.__404_shim_version = '2.0.0';

  console.log('[404] Global objects spoofed');

})();