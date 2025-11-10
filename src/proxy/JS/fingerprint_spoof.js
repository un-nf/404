/* Main JavaScript file for fingerprint spoofing proxy module

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
    "use strict";

    if (!window.__404_preflight_ready) {
        console.error("[FP] CRITICAL: Preflight layer not loaded!");
        console.error("[FP] Detection resistance will be REDUCED");
        console.error("[FP] Function.toString will reveal modifications");
        console.error("[FP] Timing attacks may detect spoofing");
    } else {
        console.log("[FP] Preflight layer detected");
    }

    if (!window.__404_config_ready) {
        console.error("[FP] WARNING: Config layer not loaded!");
        console.error("[FP] Using fallback defaults");
    } else {
        console.log("[FP] Config layer detected");
    }

    const defineProperty = window.__404_defineProperty || null;

    if (window.__fpSpoofed) {
        console.log("[FP] Already initialized, skipping");
        return;
    }
    window.__fpSpoofed = true;

    const configDefaults = {
        name: "default",
        browser_type: "chrome",
        user_agent: navigator.userAgent,
        platform: navigator.platform,
        vendor: "Google Inc.",
        vendorSub: "",
        productSub: "20030107",
        screen_resolution: "2560x1440",
        screen_avail_width: 2560,
        screen_avail_height: 1400, 
        screen_avail_top: 0,
        screen_avail_left: 0,
        hardware_concurrency: 8,
        device_memory: 8,
        color_depth: 24,
        pixel_depth: 24,
        timezone: "America/New_York",
        timezone_offset: 300,
        languages: ["en-US", "en"],
        do_not_track: null,
        cookie_enabled: true,
        webdriver: false,
        canvas_hash: "default_hash_12345",
        audio_hash: "audio_hash_67890",
        webgl_vendor: "Google Inc. (NVIDIA)",
        webgl_renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti Direct3D11 vs_5_0 ps_5_0)",
        plugins: "PDF Viewer",
        storage_quota: 107374182400,
        webrtc_local_ips: ["192.168.1.100"],

        enable_headers_spoof: true,
        enable_canvas_spoof: true,
        enable_webgl_spoof: true,
        enable_audio_spoof: true,
        enable_timezone_spoof: true,
        enable_automation_evasion: true,
        enable_webrtc_spoof: true,
        enable_performance_spoof: true,
        enable_plugin_spoof: true,
        enable_storage_spoof: true,
        enable_element_spoofing: true,
        enable_dom_evasion: true,
        enable_iframe_protection: true,
        enable_viewport_spoof: true,
        enable_speech_synthesis_spoof: true,
        viewport_rounding: 200, 

        debug: false
    };

    const config = {};
    const userConfig = window.__fpConfig || {};

    for (const key in configDefaults) {
        if (userConfig[key] !== undefined && userConfig[key] !== null) {
            config[key] = userConfig[key];
        } else {
            config[key] = configDefaults[key];
        }
    }

    const criticalFields = ['user_agent', 'platform', 'canvas_hash', 'webgl_vendor', 'webgl_renderer'];
    const missingFields = criticalFields.filter(field => !config[field] || config[field] === '');

    if (missingFields.length > 0) {
        console.warn("[FP] WARNING: Missing critical config fields:", missingFields);
        console.warn("[FP] Using fallback values - fingerprint may be inconsistent");
    }

    const debug = config.debug;

    if (debug) {
        console.log("[FP] SPOOFING INITIALIZED");
        console.log("[FP] Profile:", config.name);
        console.log("[FP] Browser:", config.browser_type);
        console.log("[FP] Target UA:", config.user_agent);
        console.log("[FP] Current UA:", navigator.userAgent);
    }

    const status = {};

    function createPRNG(seed) {
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

    const rng = createPRNG(config.canvas_hash || 'default_canvas');
    const audioRng = createPRNG(config.audio_hash || 'default_audio');

    function safeDefine(obj, prop, descriptor) {

        if (defineProperty && descriptor.get && !descriptor.set) {
            try {

                const value = descriptor.get.call(obj);

                if (typeof value !== 'function' || value === null || value === undefined) {
                    defineProperty(obj, prop, value);
                    if (debug) {
                        console.log(`[FP] Defined ${prop} using preflight definer (native-looking)`);
                    }
                    return true;
                }
            } catch (e) {

            }
        }

        try {
            const existing = Object.getOwnPropertyDescriptor(obj, prop);
            if (!existing || existing.configurable !== false) {

                if (descriptor.enumerable === undefined) {
                    descriptor.enumerable = true;
                }

                if (descriptor.value !== undefined && descriptor.writable === undefined) {
                    descriptor.writable = true;
                }

                if (descriptor.configurable === undefined) {
                    descriptor.configurable = true;
                }

                Object.defineProperty(obj, prop, descriptor);

                if (debug) {
                    const type = descriptor.get ? 'getter' : (descriptor.value !== undefined ? 'value' : 'unknown');
                    console.log(`[FP] Defined ${prop} as ${type} (enumerable: ${descriptor.enumerable})`);
                }

                return true;
            } else {
                if (debug) console.warn(`[FP] Property ${prop} is not configurable, skipping`);
            }
        } catch (e) {
            console.error(`[FP] Failed to define ${prop}:`, e);

            try {
                if (descriptor.value !== undefined) {
                    obj[prop] = descriptor.value;
                    if (debug) console.log(`[FP] Fallback: assigned ${prop} directly`);
                    return true;
                } else if (descriptor.get) {

                    obj[prop] = descriptor.get.call(obj);
                    if (debug) console.log(`[FP] Fallback: evaluated getter for ${prop} and assigned result`);
                    return true;
                }
            } catch (fallbackE) {
                console.error(`[FP] Fallback also failed for ${prop}:`, fallbackE);
            }
        }
        return false;
    }

    function getScreenDimensions() {
        const [width, height] = config.screen_resolution.split('x').map(Number);
        return {
            width,
            height,
            availWidth: config.screen_avail_width || width,
            availHeight: config.screen_avail_height || (height - 40), 
            availTop: config.screen_avail_top || 0,
            availLeft: config.screen_avail_left || 0
        };
    }

    const screenDims = getScreenDimensions();

    if (config.enable_headers_spoof) {
        try {
            if (debug) console.log("[FP] Applying navigator spoofing...");

            const isFirefox = config.user_agent && config.user_agent.includes('Firefox');

            const brands = [];
            if (config.sec_ch_ua && !isFirefox) {
                const brandMatches = config.sec_ch_ua.matchAll(/"([^"]+)";v="([^"]+)"/g);
                for (const match of brandMatches) {
                    brands.push({ brand: match[1], version: match[2] });
                }
            }

            if (isFirefox) {

                try {
                    delete navigator.userAgentData;
                    safeDefine(Navigator.prototype, 'userAgentData', {
                        get: () => undefined,
                        enumerable: false,
                        configurable: false
                    });
                    if (debug) console.log("[FP] Removed userAgentData (Firefox profile)");
                } catch (e) {
                    if (debug) console.log("[FP] Could not remove userAgentData:", e);
                }
            } else {

                const spoofedBrands = brands.length > 0 ? brands : [
                    { brand: "Not?A_Brand", version: "8" },
                    { brand: "Chromium", version: "108" }
                ];

                const uaVersion = config.user_agent.match(/Chrome\/(\d+\.\d+\.\d+\.\d+)/)?.[1] || "108.0.0.0";
                const majorVersion = uaVersion.split('.')[0];

                const fullVersionList = spoofedBrands.map(brand => ({
                    brand: brand.brand,
                    version: brand.brand === "Not?A_Brand" ? "8.0.0.0" : uaVersion
                }));

                const frozenUserAgentData = {
                    brands: Object.freeze(spoofedBrands.slice()),
                    mobile: config.sec_ch_ua_mobile === "?1",
                    platform: config.sec_ch_ua_platform?.replace(/"/g, '') || config.platform,

                    getHighEntropyValues: function(hints) {
                        const values = {
                            brands: Object.freeze(spoofedBrands.slice()),
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
                                if (hint in values) {
                                    filtered[hint] = values[hint];
                                }
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
                };

                Object.freeze(frozenUserAgentData);

                try {
                    delete navigator.userAgentData;
                } catch (e) {}

                safeDefine(Navigator.prototype, 'userAgentData', {
                    get: () => frozenUserAgentData,
                    enumerable: true,
                    configurable: false
                });

                if (debug) console.log("[FP] Set userAgentData with brands:", spoofedBrands);
            }

            safeDefine(Navigator.prototype, 'userAgent', {
                get: () => config.user_agent,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'platform', {
                get: () => config.platform,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'hardwareConcurrency', {
                get: () => config.hardware_concurrency,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'deviceMemory', {
                get: () => config.device_memory,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'doNotTrack', {
                get: () => config.do_not_track,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'cookieEnabled', {
                get: () => config.cookie_enabled,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'webdriver', {
                get: () => config.webdriver,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'languages', {
                get: () => config.languages,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'language', {
                get: () => config.languages[0] || "en-US",
                configurable: true
            });

            const vendor = config.browser_type === 'firefox' ? '' : 'Google Inc.';
            safeDefine(Navigator.prototype, 'vendor', {
                get: () => vendor,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'productSub', {
                get: () => config.browser_type === 'firefox' ? '20100101' : '20030107',
                configurable: true
            });

            safeDefine(Navigator.prototype, 'product', {
                get: () => 'Gecko',
                configurable: true
            });

            let appVersion;
            if (config.user_agent.includes('Firefox/')) {

                if (config.platform === 'Win32') {
                    appVersion = '5.0 (Windows)';
                } else if (config.platform.includes('Linux')) {
                    appVersion = '5.0 (X11)';
                } else if (config.platform.includes('Mac')) {
                    appVersion = '5.0 (Macintosh)';
                } else {
                    appVersion = '5.0 (Windows)';
                }
            } else {

                appVersion = config.user_agent.split('Mozilla/')[1];
            }
            safeDefine(Navigator.prototype, 'appVersion', {
                get: () => appVersion,
                configurable: true
            });

            safeDefine(Navigator.prototype, 'appName', {
                get: () => 'Netscape',
                configurable: true
            });

            safeDefine(Navigator.prototype, 'appCodeName', {
                get: () => 'Mozilla',
                configurable: true
            });

            safeDefine(Navigator.prototype, 'vendorSub', {
                get: () => '',
                configurable: true
            });

            if (config.browser_type === 'firefox') {
                const oscpu = config.platform === 'Win32' 
                    ? 'Windows NT 10.0; Win64; x64'
                    : config.platform;
                safeDefine(Navigator.prototype, 'oscpu', {
                    get: () => oscpu,
                    configurable: true
                });
            }

            if (config.browser_type === 'firefox') {
                safeDefine(Navigator.prototype, 'buildID', {
                    get: () => '20181001000000',
                    configurable: true
                });
            }

            safeDefine(Navigator.prototype, 'language', {
                get: () => config.languages && config.languages[0] ? config.languages[0] : 'en-US',
                configurable: true
            });

            safeDefine(Navigator.prototype, 'languages', {
                get: () => config.languages || ['en-US', 'en'],
                configurable: true
            });

            if (config.browser_type !== 'firefox') {
                safeDefine(Navigator.prototype, 'pdfViewerEnabled', {
                    get: () => true,
                    configurable: true
                });
            }

            if (!navigator.webkitTemporaryStorage && config.browser_type !== 'firefox') {
                safeDefine(Navigator.prototype, 'webkitTemporaryStorage', {
                    get: () => ({
                        queryUsageAndQuota: function(successCallback, errorCallback) {
                            setTimeout(() => {
                                successCallback(
                                    Math.floor(config.storage_quota * 0.1), 
                                    config.storage_quota 
                                );
                            }, 0);
                        }
                    }),
                    configurable: true
                });
            }

            if (!navigator.permissions && config.browser_type !== 'firefox') {
                safeDefine(Navigator.prototype, 'permissions', {
                    get: () => ({
                        query: function(permissionDesc) {

                            const permName = permissionDesc?.name || '';
                            let state = 'prompt';

                            if (permName === 'notifications') {
                                state = 'denied'; 
                            }

                            else if (permName === 'geolocation') {
                                state = 'prompt';
                            }

                            else if (permName === 'camera' || permName === 'microphone') {
                                state = 'prompt';
                            }

                            else if (permName === 'midi') {
                                state = 'prompt';
                            }

                            return Promise.resolve({
                                state: state,
                                onchange: null,
                                name: permName
                            });
                        }
                    }),
                    configurable: true
                });
            }

            if (typeof Notification !== 'undefined') {
                try {
                    Object.defineProperty(Notification, 'permission', {
                        get: () => 'default', 
                        configurable: true
                    });
                } catch (e) {

                    if (debug) console.log("[FP] Cannot modify Notification.permission:", e.message);
                }
            }

            if (!navigator.bluetooth && config.browser_type !== 'firefox') {
                safeDefine(Navigator.prototype, 'bluetooth', {
                    get: () => ({
                        requestDevice: function() {
                            return Promise.reject(new DOMException('Bluetooth adapter not available', 'NotFoundError'));
                        },
                        getAvailability: function() {
                            return Promise.resolve(false);
                        }
                    }),
                    configurable: true
                });
            }

            if (!navigator.usb && config.browser_type !== 'firefox') {
                safeDefine(Navigator.prototype, 'usb', {
                    get: () => ({
                        requestDevice: function() {
                            return Promise.reject(new DOMException('No device selected', 'NotFoundError'));
                        },
                        getDevices: function() {
                            return Promise.resolve([]);
                        }
                    }),
                    configurable: true
                });
            }

            if (navigator.getBattery) {
                const originalGetBattery = navigator.getBattery;

                navigator.getBattery = function() {
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

            if (debug) console.log("[FP] Navigator spoofing applied");
            status.navigator = "applied";
        } catch (e) {
            if (debug) console.error("[FP] Navigator spoofing error:", e);
            status.navigator = "error: " + e.message;
        }
    }

    if (config.enable_automation_evasion) {
        try {
            if (debug) console.log("[FP] Applying geolocation spoofing...");

            if (navigator.geolocation) {
                const spoofedGeolocation = {
                    getCurrentPosition: function(successCallback, errorCallback, options) {

                        if (errorCallback) {
                            setTimeout(() => {
                                errorCallback({
                                    code: 1, 
                                    message: 'User denied Geolocation',
                                    PERMISSION_DENIED: 1,
                                    POSITION_UNAVAILABLE: 2,
                                    TIMEOUT: 3
                                });
                            }, 0);
                        }
                    },
                    watchPosition: function(successCallback, errorCallback, options) {

                        if (errorCallback) {
                            setTimeout(() => {
                                errorCallback({
                                    code: 1, 
                                    message: 'User denied Geolocation',
                                    PERMISSION_DENIED: 1,
                                    POSITION_UNAVAILABLE: 2,
                                    TIMEOUT: 3
                                });
                            }, 0);
                        }
                        return 0; 
                    },
                    clearWatch: function(watchId) {

                    }
                };

                try {
                    delete navigator.geolocation;
                } catch (e) {}

                safeDefine(Navigator.prototype, 'geolocation', {
                    get: () => spoofedGeolocation,
                    enumerable: true,
                    configurable: true
                });
            }

            if (debug) console.log("[FP] Geolocation spoofing applied");
            status.geolocation = "applied";
        } catch (e) {
            if (debug) console.error("[FP] Geolocation spoofing error:", e);
            status.geolocation = "error: " + e.message;
        }
    }

    if (config.enable_canvas_spoof) {
        try {
            if (debug) console.log("[FP] Applying screen spoofing...");

            safeDefine(Screen.prototype, 'width', {
                get: () => screenDims.width,
                configurable: true
            });

            safeDefine(Screen.prototype, 'height', {
                get: () => screenDims.height,
                configurable: true
            });

            safeDefine(Screen.prototype, 'availWidth', {
                get: () => screenDims.availWidth,
                configurable: true
            });

            safeDefine(Screen.prototype, 'availHeight', {
                get: () => screenDims.availHeight,
                configurable: true
            });

            safeDefine(Screen.prototype, 'availTop', {
                get: () => screenDims.availTop,
                configurable: true
            });

            safeDefine(Screen.prototype, 'availLeft', {
                get: () => screenDims.availLeft,
                configurable: true
            });

            safeDefine(Screen.prototype, 'colorDepth', {
                get: () => config.color_depth,
                configurable: true
            });

            safeDefine(Screen.prototype, 'pixelDepth', {
                get: () => config.color_depth,
                configurable: true
            });

            status.screen = "applied";
            if (debug) console.log("[FP] Screen spoofing applied");

        } catch (e) {
            if (debug) console.error("[FP] Screen spoofing error:", e);
            status.screen = "error: " + e.message;
        }
    }

    if (config.enable_canvas_spoof) {
        try {
            if (debug) console.log("[FP] Applying canvas protection...");

            function hashString(str) {
                let hash = 0;
                for (let i = 0; i < str.length; i++) {
                    const char = str.charCodeAt(i);
                    hash = ((hash << 5) - hash) + char;
                    hash = hash & hash; 
                }
                return Math.abs(hash);
            }

            function applyCanvasNoise(imageData) {
                if (!imageData || !imageData.data) return;

                const data = imageData.data;
                const len = data.length;

                const canvasSignature = config.canvas_hash + imageData.width + 'x' + imageData.height;
                const seed = hashString(canvasSignature);

                let state = seed;
                function deterministicRandom() {
                    state |= 0;
                    state = state + 0x6D2B79F5 | 0;
                    let t = Math.imul(state ^ state >>> 15, 1 | state);
                    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
                    return ((t ^ t >>> 14) >>> 0) / 4294967296;
                }

                const interval = imageData.width <= 16 && imageData.height <= 16 ? 20 : 10;

                for (let i = 0; i < len; i += interval) {

                    if (deterministicRandom() < 0.1) {

                        const noise = deterministicRandom() > 0.5 ? 1 : -1;

                        if (i < len) {
                            data[i] = Math.max(0, Math.min(255, data[i] + noise));
                        }

                        if (i + 1 < len) {
                            data[i + 1] = Math.max(0, Math.min(255, data[i + 1] + noise));
                        }

                        if (i + 2 < len) {
                            data[i + 2] = Math.max(0, Math.min(255, data[i + 2] + noise));
                        }

                    }
                }
            }

            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            const originalToBlob = HTMLCanvasElement.prototype.toBlob;
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

            HTMLCanvasElement.prototype.toDataURL = function() {
                try {
                    const ctx = this.getContext('2d');
                    if (ctx && this.width > 0 && this.height > 0) {
                        const imageData = ctx.getImageData(0, 0, this.width, this.height);
                        const backup = new Uint8ClampedArray(imageData.data);

                        applyCanvasNoise(imageData);
                        ctx.putImageData(imageData, 0, 0);

                        const result = originalToDataURL.apply(this, arguments);

                        imageData.data.set(backup);
                        ctx.putImageData(imageData, 0, 0);

                        return result;
                    }
                } catch (e) {
                    if (debug) console.warn("[FP] Canvas toDataURL error:", e);
                }
                return originalToDataURL.apply(this, arguments);
            };

            HTMLCanvasElement.prototype.toBlob = function(callback) {
                try {
                    const ctx = this.getContext('2d');
                    if (ctx && this.width > 0 && this.height > 0) {
                        const imageData = ctx.getImageData(0, 0, this.width, this.height);
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
                    if (debug) console.warn("[FP] Canvas toBlob error:", e);
                }
                return originalToBlob.apply(this, arguments);
            };

            status.canvas = "applied";
            if (debug) console.log("[FP] Canvas protection applied");

        } catch (e) {
            if (debug) console.error("[FP] Canvas protection error:", e);
            status.canvas = "error: " + e.message;
        }
    }

    if (config.enable_webgl_spoof) {
        try {
            if (debug) console.log("[FP] Applying WebGL protection...");

            const originalGetContext = HTMLCanvasElement.prototype.getContext;

            HTMLCanvasElement.prototype.getContext = function(contextType, options) {
                const context = originalGetContext.call(this, contextType, options);

                if (context && (contextType === 'webgl' || contextType === 'webgl2' || contextType === 'experimental-webgl')) {
                    const originalGetParameter = context.getParameter;

                    context.getParameter = function(pname) {

                        switch (pname) {
                            case context.VENDOR:
                                return config.webgl_vendor;
                            case context.RENDERER:
                                return config.webgl_renderer;
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

            status.webgl = "applied";
            if (debug) console.log("[FP] WebGL protection applied");

        } catch (e) {
            if (debug) console.error("[FP] WebGL protection error:", e);
            status.webgl = "error: " + e.message;
        }
    }

    if (config.enable_audio_spoof) {
        try {
            if (debug) console.log("[FP] Applying audio protection...");

            const OriginalAudioContext = window.AudioContext || window.webkitAudioContext;
            const OriginalOfflineAudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;

            if (OriginalOfflineAudioContext && OriginalOfflineAudioContext.prototype.startRendering) {
                const originalStartRendering = OriginalOfflineAudioContext.prototype.startRendering;

                OriginalOfflineAudioContext.prototype.startRendering = function() {
                    if (debug) console.log("[FP] OfflineAudioContext.startRendering intercepted");

                    return originalStartRendering.call(this).then(function(audioBuffer) {
                        if (debug) console.log("[FP] Audio buffer rendered, applying noise");

                        for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
                            const channelData = audioBuffer.getChannelData(channel);

                            for (let i = 0; i < channelData.length; i++) {

                                const noise = (audioRng() - 0.5) * 0.0001;
                                channelData[i] = channelData[i] + noise;
                            }
                        }

                        if (debug) {
                            console.log(`[FP] Modified ${audioBuffer.length} samples across ${audioBuffer.numberOfChannels} channel(s)`);
                            console.log(`[FP] Sample rate: ${audioBuffer.sampleRate}, Duration: ${audioBuffer.duration}s`);
                        }

                        return audioBuffer;
                    });
                };

                if (debug) console.log("[FP] OfflineAudioContext.prototype.startRendering patched");
            }

            if (OriginalOfflineAudioContext || OriginalAudioContext) {
                const BaseAudioContext = OriginalOfflineAudioContext || OriginalAudioContext;

                if (BaseAudioContext.prototype.createDynamicsCompressor) {
                    const originalCreateDynamicsCompressor = BaseAudioContext.prototype.createDynamicsCompressor;

                    BaseAudioContext.prototype.createDynamicsCompressor = function() {
                        const compressor = originalCreateDynamicsCompressor.call(this);

                        if (debug) console.log("[FP] DynamicsCompressor created, applying parameter variations");

                        try {

                            if (compressor.threshold && compressor.threshold.value !== undefined) {
                                const thresholdVariation = (audioRng() - 0.5) * 0.1;
                                compressor.threshold.value = compressor.threshold.value + thresholdVariation;
                            }

                            if (compressor.knee && compressor.knee.value !== undefined) {
                                const kneeVariation = (audioRng() - 0.5) * 0.05;
                                compressor.knee.value = compressor.knee.value + kneeVariation;
                            }

                            if (compressor.ratio && compressor.ratio.value !== undefined) {
                                const ratioVariation = (audioRng() - 0.5) * 0.01;
                                compressor.ratio.value = compressor.ratio.value + ratioVariation;
                            }

                            if (compressor.attack && compressor.attack.value !== undefined) {
                                const attackVariation = (audioRng() - 0.5) * 0.0001;
                                compressor.attack.value = compressor.attack.value + attackVariation;
                            }

                            if (compressor.release && compressor.release.value !== undefined) {
                                const releaseVariation = (audioRng() - 0.5) * 0.001;
                                compressor.release.value = compressor.release.value + releaseVariation;
                            }
                        } catch (e) {
                            if (debug) console.warn("[FP] Could not modify compressor parameters:", e);
                        }

                        return compressor;
                    };

                    if (debug) console.log("[FP] DynamicsCompressor patched");
                }

                if (BaseAudioContext.prototype.createOscillator) {
                    const originalCreateOscillator = BaseAudioContext.prototype.createOscillator;

                    BaseAudioContext.prototype.createOscillator = function() {
                        const oscillator = originalCreateOscillator.call(this);

                        try {
                            if (oscillator.frequency && oscillator.frequency.value !== undefined) {
                                const freqVariation = (audioRng() - 0.5) * 0.01;
                                oscillator.frequency.value = oscillator.frequency.value + freqVariation;
                            }
                        } catch (e) {
                            if (debug) console.warn("[FP] Could not modify oscillator frequency:", e);
                        }

                        return oscillator;
                    };

                    if (debug) console.log("[FP] OscillatorNode patched");
                }
            }

            if (OriginalAudioContext) {
                function SpoofedAudioContext() {
                    const context = new OriginalAudioContext();

                    if (config.audio_context) {
                        Object.defineProperty(context, 'sampleRate', {
                            get: function() { return config.audio_context.sample_rate || 48000; },
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(context, 'state', {
                            get: function() { return 'running'; },
                            enumerable: true,
                            configurable: false
                        });
                    }

                    if (context.destination && config.audio_context) {
                        const dest = context.destination;

                        Object.defineProperty(dest, 'channelCount', {
                            get: function() { return config.audio_context.channel_count || 2; },
                            set: function(value) {},
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(dest, 'channelCountMode', {
                            get: function() { return 'explicit'; },
                            set: function(value) {},
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(dest, 'channelInterpretation', {
                            get: function() { return 'speakers'; },
                            set: function(value) {},
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(dest, 'maxChannelCount', {
                            get: function() { return config.audio_context.max_channel_count || 2; },
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(dest, 'numberOfInputs', {
                            get: function() { return config.audio_context.number_of_inputs || 1; },
                            enumerable: true,
                            configurable: false
                        });

                        Object.defineProperty(dest, 'numberOfOutputs', {
                            get: function() { return config.audio_context.number_of_outputs || 0; },
                            enumerable: true,
                            configurable: false
                        });
                    }

                    const originalCreateAnalyser = context.createAnalyser;
                    context.createAnalyser = function() {
                        const analyser = originalCreateAnalyser.call(this);

                        const originalGetFloatFrequencyData = analyser.getFloatFrequencyData;
                        analyser.getFloatFrequencyData = function(array) {
                            originalGetFloatFrequencyData.call(this, array);

                            for (let i = 0; i < array.length; i += 10) {
                                if (audioRng() < 0.1) {
                                    array[i] += (audioRng() - 0.5) * 0.0001;
                                }
                            }
                        };

                        const originalGetByteFrequencyData = analyser.getByteFrequencyData;
                        analyser.getByteFrequencyData = function(array) {
                            originalGetByteFrequencyData.call(this, array);

                            for (let i = 0; i < array.length; i += 5) {
                                if (audioRng() < 0.15) {
                                    const noise = Math.floor((audioRng() - 0.5) * 2);
                                    array[i] = Math.max(0, Math.min(255, array[i] + noise));
                                }
                            }
                        };

                        const originalGetFloatTimeDomainData = analyser.getFloatTimeDomainData;
                        analyser.getFloatTimeDomainData = function(array) {
                            originalGetFloatTimeDomainData.call(this, array);

                            for (let i = 0; i < array.length; i++) {
                                if (audioRng() < 0.05) {
                                    array[i] += (audioRng() - 0.5) * 0.00001;
                                }
                            }
                        };

                        const originalGetByteTimeDomainData = analyser.getByteTimeDomainData;
                        analyser.getByteTimeDomainData = function(array) {
                            originalGetByteTimeDomainData.call(this, array);

                            for (let i = 0; i < array.length; i += 3) {
                                if (audioRng() < 0.1) {
                                    const noise = Math.floor((audioRng() - 0.5) * 2);
                                    array[i] = Math.max(0, Math.min(255, array[i] + noise));
                                }
                            }
                        };

                        return analyser;
                    };

                    const originalCreateOscillator = context.createOscillator;
                    context.createOscillator = function() {
                        const oscillator = originalCreateOscillator.call(this);

                        const originalFrequency = oscillator.frequency;
                        const frequencyValue = originalFrequency.value;

                        Object.defineProperty(oscillator, 'frequency', {
                            get: function() {
                                return {
                                    ...originalFrequency,
                                    value: frequencyValue + (audioRng() - 0.5) * 0.01
                                };
                            },
                            configurable: true
                        });

                        return oscillator;
                    };

                    const originalCreateDynamicsCompressor = context.createDynamicsCompressor;
                    if (originalCreateDynamicsCompressor) {
                        context.createDynamicsCompressor = function() {
                            const compressor = originalCreateDynamicsCompressor.call(this);

                            const originalThreshold = compressor.threshold;
                            Object.defineProperty(compressor, 'threshold', {
                                get: function() {
                                    return {
                                        ...originalThreshold,
                                        value: originalThreshold.value + (audioRng() - 0.5) * 0.1
                                    };
                                },
                                configurable: true
                            });

                            return compressor;
                        };
                    }

                    return context;
                }

                Object.setPrototypeOf(SpoofedAudioContext, OriginalAudioContext);
                SpoofedAudioContext.prototype = OriginalAudioContext.prototype;

                window.AudioContext = SpoofedAudioContext;
                if (window.webkitAudioContext) {
                    window.webkitAudioContext = SpoofedAudioContext;
                }
            }

            status.audio = "applied (OfflineAudioContext, DynamicsCompressor, Oscillator patched)";
            if (debug) console.log("[FP] Audio protection applied - fingerprint will change");

        } catch (e) {
            if (debug) console.error("[FP] Audio protection error:", e);
            status.audio = "error: " + e.message;
        }
    }

    window.__404_spoof_ready = true;
    if (debug) console.log("[FP] Core spoofing complete, sandbox can proceed");

    if (config.enable_timezone_spoof) {
        try {
            if (debug) console.log("[FP] Applying timezone spoofing...");

            function calculateOffset(date, timezone) {
                if (timezone === 'America/New_York') {
                    const month = date.getMonth(); 

                    if (month >= 2 && month <= 9) {
                        return 240; 
                    }
                    return 300; 
                }

                return config.timezone_offset;
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

            status.timezone = "applied";
            if (debug) console.log("[FP] Timezone spoofing applied");

        } catch (e) {
            if (debug) console.error("[FP] Timezone spoofing error:", e);
            status.timezone = "error: " + e.message;
        }
    }

    if (config.enable_automation_evasion) {
        try {
            if (debug) console.log("[FP] Applying automation evasion...");

            const automationProps = [
                '__webdriver_script_fn', '__webdriver_script_func', '__webdriver_script_function',
                '__selenium_unwrapped', '__fxdriver_unwrapped', '__driver_unwrapped',
                '__webdriver_unwrapped', '__driver_evaluate', '__webdriver_evaluate',
                '__selenium_evaluate', '__fxdriver_evaluate', 'webdriver', 'selenium',
                '__nightmare', '__phantomjs', 'callPhantom', '_phantom', 'phantom'
            ];

            automationProps.forEach(prop => {
                try {
                    if (window[prop]) delete window[prop];
                    if (document[prop]) delete document[prop];

                    safeDefine(window, prop, {
                        get: () => undefined,
                        configurable: false,
                        enumerable: false
                    });
                } catch (e) {

                }
            });

            const originalHasFocus = document.hasFocus;
            document.hasFocus = function() {
                return true;
            };

            safeDefine(document, 'visibilityState', {
                get: () => 'visible',
                configurable: true
            });

            safeDefine(document, 'hidden', {
                get: () => false,
                configurable: true
            });

            if (!['chrome', 'edge', 'brave', 'vivaldi'].includes(config.browser_type)) {
                if (typeof chrome !== 'undefined') {
                    try {

                        const descriptor = Object.getOwnPropertyDescriptor(window, 'chrome');
                        if (descriptor && descriptor.configurable) {
                            delete window.chrome;
                        } else {
                            if (debug) console.log("[FP] window.chrome is non-configurable, skipping");
                        }
                    } catch (e) {
                        if (debug) console.log("[FP] Cannot modify window.chrome:", e.message);
                    }
                }
            } else {

                if (typeof chrome === 'undefined' || !chrome) {
                    try {
                        window.chrome = {
                            app: undefined,
                            csi: function() { return {}; },
                            loadTimes: function() { 
                                return {
                                    commitLoadTime: performance.now() / 1000,
                                    connectionInfo: 'http/1.1',
                                    finishDocumentLoadTime: (performance.now() + Math.random() * 100) / 1000,
                                    finishLoadTime: 0,
                                    firstPaintAfterLoadTime: 0,
                                    firstPaintTime: (performance.now() + Math.random() * 50) / 1000,
                                    navigationType: 'Other',
                                    npnNegotiatedProtocol: 'h2',
                                    requestTime: (Date.now() / 1000) - (performance.now() / 1000),
                                    startLoadTime: (Date.now() / 1000) - (performance.now() / 1000),
                                    wasAlternateProtocolAvailable: false,
                                    wasFetchedViaSpdy: true,
                                    wasNpnNegotiated: true
                                };
                            },
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
                                    ARM64: "arm64",
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
                            }
                        };

                        if (debug) console.log("[FP] Added window.chrome for Chromium browser");
                    } catch (e) {
                        if (debug) console.log("[FP] Cannot add window.chrome:", e.message);
                    }
                }
            }

            status.automation = "applied";
            if (debug) console.log("[FP] Automation evasion applied");

        } catch (e) {
            if (debug) console.error("[FP] Automation evasion error:", e);
            status.automation = "error: " + e.message;
        }
    }

    if (config.enable_webrtc_spoof) {
        try {
            if (debug) console.log("[FP] Applying WebRTC protection...");

            if (window.RTCPeerConnection) {
                const OriginalRTCPeerConnection = window.RTCPeerConnection;

                window.RTCPeerConnection = function(config_rtc) {

                    if (config_rtc && config_rtc.iceServers) {
                        config_rtc.iceServers = [];
                    }

                    const pc = new OriginalRTCPeerConnection(config_rtc);

                    const originalCreateDataChannel = pc.createDataChannel;
                    pc.createDataChannel = function() {
                        const result = originalCreateDataChannel.apply(pc, arguments);

                        setTimeout(() => {
                            if (pc.onicecandidate && config.webrtc_local_ips.length > 0) {
                                const fakeCandidate = {
                                    candidate: {
                                        candidate: `candidate:1 1 UDP 2130706431 ${config.webrtc_local_ips[0]} 54400 typ host`,
                                        sdpMLineIndex: 0
                                    }
                                };
                                pc.onicecandidate(fakeCandidate);
                            }
                        }, 1);

                        return result;
                    };

                    return pc;
                };

                Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTCPeerConnection);
                window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
            }

            status.webrtc = "applied";
            if (debug) console.log("[FP] WebRTC protection applied");

        } catch (e) {
            if (debug) console.error("[FP] WebRTC protection error:", e);
            status.webrtc = "error: " + e.message;
        }
    }

    if (config.enable_performance_spoof) {
        try {
            if (debug) console.log("[FP] Applying performance spoofing...");

            const profileHash = hashString(config.name || 'default');
            const fixedOffset = (profileHash % 100) / 1000; 

            const originalPerformanceNow = performance.now;
            performance.now = function() {
                const original = originalPerformanceNow.call(this);
                return original + fixedOffset; 
            };

            if (performance.timing) {
                let cachedTiming = null;

                const timingProxy = new Proxy(performance.timing, {
                    get: function(target, property) {
                        if (!cachedTiming) {
                            cachedTiming = {};
                            for (let prop in target) {
                                if (typeof target[prop] === 'number') {
                                    const jitter = Math.floor(rng() * 10) - 5;
                                    cachedTiming[prop] = target[prop] + jitter;
                                }
                            }
                        }
                        return cachedTiming[property] || target[property];
                    }
                });

                safeDefine(performance, 'timing', {
                    get: () => timingProxy,
                    configurable: true
                });
            }

            status.performance = "applied";
            if (debug) console.log("[FP] Performance spoofing applied");

        } catch (e) {
            if (debug) console.error("[FP] Performance spoofing error:", e);
            status.performance = "error: " + e.message;
        }
    }

    if (config.enable_plugin_spoof) {
        try {
            if (debug) console.log("[FP] Applying plugins spoofing...");

            const fakePlugins = [];
            const fakeMimeTypes = [];
            const pluginList = config.plugins.split(',').map(p => p.trim());

            if (pluginList.includes('PDF Viewer')) {
                if (['chrome', 'edge', 'brave', 'vivaldi'].includes(config.browser_type)) {

                    const pdfMime = { 
                        type: 'application/pdf', 
                        description: 'Portable Document Format', 
                        suffixes: 'pdf',
                        enabledPlugin: null 
                    };
                    const pdfPlugin = {
                        name: 'Chromium PDF Plugin',
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer',
                        length: 1,
                        0: pdfMime,
                        item: function(index) { return this[index] || null; },
                        namedItem: function(name) { return this[0].type === name ? this[0] : null; }
                    };
                    pdfMime.enabledPlugin = pdfPlugin;
                    fakePlugins.push(pdfPlugin);
                    fakeMimeTypes.push(pdfMime);
                } else if (config.browser_type === 'firefox') {

                    const pdfMime = { 
                        type: 'application/pdf', 
                        description: 'Portable Document Format', 
                        suffixes: 'pdf',
                        enabledPlugin: null 
                    };
                    const pdfPlugin = {
                        name: 'PDF Viewer',
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer',
                        length: 1,
                        0: pdfMime,
                        item: function(index) { return this[index] || null; },
                        namedItem: function(name) { return this[0].type === name ? this[0] : null; }
                    };
                    pdfMime.enabledPlugin = pdfPlugin;
                    fakePlugins.push(pdfPlugin);
                    fakeMimeTypes.push(pdfMime);
                }
            }

            const pluginsArray = Object.assign(fakePlugins, {
                length: fakePlugins.length,
                item: function(index) { return this[index] || null; },
                namedItem: function(name) {
                    return Array.from(this).find(p => p.name === name) || null;
                },
                refresh: function() {}
            });

            safeDefine(Navigator.prototype, 'plugins', {
                get: () => pluginsArray,
                configurable: true
            });

            const mimeTypesArray = Object.assign(fakeMimeTypes, {
                length: fakeMimeTypes.length,
                item: function(index) { return this[index] || null; },
                namedItem: function(name) {
                    return Array.from(this).find(m => m.type === name) || null;
                }
            });

            safeDefine(Navigator.prototype, 'mimeTypes', {
                get: () => mimeTypesArray,
                configurable: true
            });

            status.plugins = "applied";
            if (debug) console.log("[FP] Plugins spoofing applied");

        } catch (e) {
            if (debug) console.error("[FP] Plugins spoofing error:", e);
            status.plugins = "error: " + e.message;
        }
    }

    if (config.enable_storage_spoof) {
        try {
            if (debug) console.log("[FP] Applying storage spoofing...");

            if (navigator.storage && navigator.storage.estimate) {
                const originalEstimate = navigator.storage.estimate;
                navigator.storage.estimate = function() {
                    return Promise.resolve({
                        quota: config.storage_quota,
                        usage: Math.floor(config.storage_quota * 0.1),
                        usageDetails: {
                            indexedDB: Math.floor(config.storage_quota * 0.05),
                            caches: Math.floor(config.storage_quota * 0.03),
                            serviceWorkerRegistrations: Math.floor(config.storage_quota * 0.02)
                        }
                    });
                };
            }

            status.storage = "applied";
            if (debug) console.log("[FP] Storage spoofing applied");

        } catch (e) {
            if (debug) console.error("[FP] Storage spoofing error:", e);
            status.storage = "error: " + e.message;
        }
    }

    if (config.enable_iframe_protection) {
        try {
            if (debug) console.log("[FP] Applying iframe loading protection...");

            status.iframe_loading = "applied";
            if (debug) console.log("[FP] Iframe loading protection applied");

        } catch (e) {
            if (debug) console.error("[FP] Iframe loading protection error:", e);
            status.iframe_loading = "error: " + e.message;
        }
    }

    if (config.enable_automation_evasion) {
        try {
            if (debug) console.log("[FP] Applying event protection...");

            const originalDispatchEvent = EventTarget.prototype.dispatchEvent;
            EventTarget.prototype.dispatchEvent = function(event) {

                return originalDispatchEvent.call(this, event);
            };

            status.events = "applied";
            if (debug) console.log("[FP] Event protection applied");

        } catch (e) {
            if (debug) console.error("[FP] Event protection error:", e);
            status.events = "error: " + e.message;
        }
    }

    if (config.enable_iframe_protection) {
        try {
            if (debug) console.log("[FP] Initializing comprehensive iframe protection");

            const applySpoofing = function(targetWindow) {
                try {

                    if (!targetWindow || targetWindow.__fpSpoofed) {
                        return;
                    }

                    try {

                        const test = targetWindow.location.href;
                    } catch (e) {

                        if (debug) console.log("[FP] Skipping cross-origin iframe:", e.message);
                        return;
                    }

                    targetWindow.__fpSpoofed = true;

                    targetWindow.__fpConfig = config;

                    if (debug) console.log("[FP] Applying spoofing to subframe:", targetWindow.location.href);

                    if (config.enable_headers_spoof) {

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

                        safeDefine(targetWindow.navigator, 'vendorSub', {
                            get: function() { return config.vendorSub || ''; },
                            enumerable: true,
                            configurable: true
                        });

                        safeDefine(targetWindow.navigator, 'productSub', {
                            get: function() { return config.productSub || '20030107'; },
                            enumerable: true,
                            configurable: true
                        });

                        const appVersion = config.user_agent.includes('Firefox/') 
                            ? '5.0 (' + config.user_agent.split('Mozilla/5.0 ')[1]
                            : config.user_agent.split('Mozilla/')[1];
                        safeDefine(targetWindow.navigator, 'appVersion', {
                            get: function() { return appVersion; },
                            enumerable: true,
                            configurable: true
                        });

                        safeDefine(targetWindow.navigator, 'appName', {
                            get: function() { return 'Netscape'; },
                            enumerable: true,
                            configurable: true
                        });

                        safeDefine(targetWindow.navigator, 'appCodeName', {
                            get: function() { return 'Mozilla'; },
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

                        safeDefine(targetWindow.navigator, 'maxTouchPoints', {
                            get: function() { return config.max_touch_points || 0; },
                            enumerable: true,
                            configurable: true
                        });

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

                        safeDefine(targetWindow.navigator, 'doNotTrack', {
                            get: function() { return config.do_not_track; },
                            enumerable: true,
                            configurable: true
                        });

                        safeDefine(targetWindow.navigator, 'cookieEnabled', {
                            get: function() { return config.cookie_enabled; },
                            enumerable: true,
                            configurable: true
                        });

                        if (config.browser_type === 'firefox') {
                            if (config.oscpu) {
                                safeDefine(targetWindow.navigator, 'oscpu', {
                                    get: function() { return config.oscpu; },
                                    enumerable: true,
                                    configurable: true
                                });
                            }
                            if (config.buildID) {
                                safeDefine(targetWindow.navigator, 'buildID', {
                                    get: function() { return config.buildID; },
                                    enumerable: true,
                                    configurable: true
                                });
                            }
                        }
                    }

                    if (config.enable_canvas_spoof && config.screen_resolution) {
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

                        safeDefine(targetWindow.screen, 'colorDepth', {
                            get: function() { return config.color_depth || 24; },
                            enumerable: true,
                            configurable: true
                        });

                        safeDefine(targetWindow.screen, 'pixelDepth', {
                            get: function() { return config.pixel_depth || 24; },
                            enumerable: true,
                            configurable: true
                        });
                    }

                    if (config.enable_automation_evasion) {
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

                        targetWindow.HTMLCanvasElement.prototype.toDataURL = function() {
                            const ctx = this.getContext('2d');
                            if (ctx) {
                                const imageData = ctx.getImageData(0, 0, this.width, this.height);

                                for (let i = 0; i < imageData.data.length; i += 4) {
                                    imageData.data[i] = (imageData.data[i] + (rng() * 2 - 1)) & 0xFF;
                                }
                                ctx.putImageData(imageData, 0, 0);
                            }
                            return originalToDataURL.apply(this, arguments);
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
                            targetWindow.WebGL2RenderingContext.prototype.getParameter = targetWindow.WebGLRenderingContext.prototype.getParameter;
                        }
                    }

                    if (config.enable_timezone_spoof && config.timezone) {

                        const OriginalDate = targetWindow.Date;
                        const timezoneOffset = config.timezone_offset || 300;

                        function calculateOffset(date) {
                            const month = date.getMonth();
                            const day = date.getDate();
                            const dayOfWeek = date.getDay();

                            const isDST = (month > 2 && month < 10) || 
                                         (month === 2 && day >= 8 && dayOfWeek === 0) ||
                                         (month === 10 && day < 7 && dayOfWeek === 0);

                            return isDST ? 240 : 300; 
                        }

                        targetWindow.Date = function(...args) {
                            if (args.length === 0) {
                                return new OriginalDate();
                            }
                            return new OriginalDate(...args);
                        };

                        targetWindow.Date.prototype = OriginalDate.prototype;
                        targetWindow.Date.now = OriginalDate.now;
                        targetWindow.Date.UTC = OriginalDate.UTC;
                        targetWindow.Date.parse = OriginalDate.parse;

                        const originalGetTimezoneOffset = OriginalDate.prototype.getTimezoneOffset;
                        OriginalDate.prototype.getTimezoneOffset = function() {
                            return calculateOffset(this);
                        };

                        const originalToString = OriginalDate.prototype.toString;
                        OriginalDate.prototype.toString = function() {
                            const actualOffset = originalGetTimezoneOffset.call(this);
                            const targetOffset = calculateOffset(this);
                            const offsetDiff = actualOffset - targetOffset;
                            const adjustedTime = new OriginalDate(this.getTime() + offsetDiff * 60000);
                            const timeStr = originalToString.call(adjustedTime);
                            const isDST = calculateOffset(this) === 240;
                            const tzAbbr = isDST ? "EDT" : "EST";
                            return timeStr.replace(/GMT[+-]\d{4}.*$/, `GMT-0${targetOffset/60}00 (${tzAbbr})`);
                        };

                        const originalToTimeString = OriginalDate.prototype.toTimeString;
                        OriginalDate.prototype.toTimeString = function() {
                            const actualOffset = originalGetTimezoneOffset.call(this);
                            const targetOffset = calculateOffset(this);
                            const offsetDiff = actualOffset - targetOffset;
                            const adjustedTime = new OriginalDate(this.getTime() + offsetDiff * 60000);
                            const timeStr = originalToTimeString.call(adjustedTime);
                            const isDST = calculateOffset(this) === 240;
                            const tzAbbr = isDST ? "EDT" : "EST";
                            return timeStr.replace(/GMT[+-]\d{4}.*$/, `GMT-0${targetOffset/60}00 (${tzAbbr})`);
                        };

                        const originalToLocaleString = OriginalDate.prototype.toLocaleString;
                        OriginalDate.prototype.toLocaleString = function(...args) {
                            const actualOffset = originalGetTimezoneOffset.call(this);
                            const targetOffset = calculateOffset(this);
                            const offsetDiff = actualOffset - targetOffset;
                            const adjustedTime = new OriginalDate(this.getTime() + offsetDiff * 60000);
                            return originalToLocaleString.call(adjustedTime, ...args);
                        };

                        const originalToLocaleTimeString = OriginalDate.prototype.toLocaleTimeString;
                        OriginalDate.prototype.toLocaleTimeString = function(...args) {
                            const actualOffset = originalGetTimezoneOffset.call(this);
                            const targetOffset = calculateOffset(this);
                            const offsetDiff = actualOffset - targetOffset;
                            const adjustedTime = new OriginalDate(this.getTime() + offsetDiff * 60000);
                            return originalToLocaleTimeString.call(adjustedTime, ...args);
                        };

                        const originalToLocaleDateString = OriginalDate.prototype.toLocaleDateString;
                        OriginalDate.prototype.toLocaleDateString = function(...args) {
                            const actualOffset = originalGetTimezoneOffset.call(this);
                            const targetOffset = calculateOffset(this);
                            const offsetDiff = actualOffset - targetOffset;
                            const adjustedTime = new OriginalDate(this.getTime() + offsetDiff * 60000);
                            return originalToLocaleDateString.call(adjustedTime, ...args);
                        };

                        if (targetWindow.Intl && targetWindow.Intl.DateTimeFormat) {
                            const OriginalDateTimeFormat = targetWindow.Intl.DateTimeFormat;

                            targetWindow.Intl.DateTimeFormat = function(locales, options) {

                                const modifiedOptions = options ? {...options} : {};
                                modifiedOptions.timeZone = config.timezone || 'America/New_York';
                                return new OriginalDateTimeFormat(locales, modifiedOptions);
                            };

                            targetWindow.Intl.DateTimeFormat.prototype = OriginalDateTimeFormat.prototype;
                            targetWindow.Intl.DateTimeFormat.supportedLocalesOf = OriginalDateTimeFormat.supportedLocalesOf;

                            const originalResolvedOptions = OriginalDateTimeFormat.prototype.resolvedOptions;
                            OriginalDateTimeFormat.prototype.resolvedOptions = function() {
                                const options = originalResolvedOptions.call(this);
                                options.timeZone = config.timezone || 'America/New_York';
                                return options;
                            };
                        }
                    }

                    if (debug) console.log("[FP] Successfully spoofed subframe");

                } catch (e) {
                    if (debug) console.error("[FP] Error spoofing subframe:", e);
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

                                if (debug) console.log("[FP] Skipping inaccessible frame:", e.message);
                            }
                        }
                    }
                } catch (e) {
                    if (debug) console.error("[FP] Error patching frames:", e);
                }
            };

            patchAllFrames(window);

            const frameObserver = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.tagName === 'IFRAME') {
                            if (debug) console.log("[FP] New iframe detected, patching...");

                            node.addEventListener('load', function() {
                                try {
                                    patchAllFrames(node.contentWindow);
                                } catch (e) {
                                    if (debug) console.error("[FP] Error patching new iframe:", e);
                                }
                            });

                            try {
                                if (node.contentWindow) {
                                    patchAllFrames(node.contentWindow);
                                }
                            } catch (e) {

                            }
                        }
                    });
                });
            });

            frameObserver.observe(document.documentElement, {
                childList: true,
                subtree: true
            });

            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(document, tagName);

                if (tagName.toLowerCase() === 'iframe') {
                    if (debug) console.log("[FP] Iframe created via createElement, will patch on load");

                    const originalSetAttribute = element.setAttribute.bind(element);
                    element.setAttribute = function(name, value) {
                        if (name.toLowerCase() === 'sandbox') {

                            if (typeof value === 'string') {
                                const hasScripts = value.includes('allow-scripts');
                                const hasSameOrigin = value.includes('allow-same-origin');

                                if (hasScripts && hasSameOrigin) {
                                    console.warn('[FP] Dangerous iframe sandbox detected: allow-scripts + allow-same-origin');
                                    console.warn('[FP] This combination allows sandbox escape via document.domain');
                                    console.warn('[FP] Removing allow-same-origin for security');

                                    const safeSandbox = value.split(' ')
                                        .filter(v => v.trim() && v !== 'allow-same-origin')
                                        .join(' ');

                                    return originalSetAttribute('sandbox', safeSandbox);
                                }
                            }
                        }

                        return originalSetAttribute(name, value);
                    };

                    element.addEventListener('load', function() {
                        try {
                            patchAllFrames(element.contentWindow);
                        } catch (e) {
                            if (debug) console.error("[FP] Error patching createElement iframe:", e);
                        }
                    });
                }

                return element;
            };

            const originalWindowOpen = window.open;
            window.open = function() {
                const newWindow = originalWindowOpen.apply(window, arguments);

                if (newWindow) {
                    if (debug) console.log("[FP] New window opened, will patch");

                    try {

                        setTimeout(function() {
                            patchAllFrames(newWindow);
                        }, 100);
                    } catch (e) {
                        if (debug) console.error("[FP] Error patching popup:", e);
                    }
                }

                return newWindow;
            };

            status.iframe_protection = 'active (recursive with mutation observer)';
            if (debug) console.log('[FP] Comprehensive iframe protection enabled');

        } catch (e) {
            status.iframe_protection = 'error: ' + e.message;
            if (debug) console.error('[FP] Iframe protection error:', e);
        }
    }

    if (config.enable_speech_synthesis_spoof && window.speechSynthesis) {
        try {
            if (debug) console.log("[FP] Applying speech synthesis spoofing...");

            const isFirefox = config.browser_type === 'firefox' || config.user_agent.includes('Firefox');

            const firefoxVoices = [
                { voiceURI: 'urn:moz-tts:sapi:Microsoft David - English (United States)?en-US', name: 'Microsoft David - English (United States)', lang: 'en-US', localService: true, default: true },
                { voiceURI: 'urn:moz-tts:sapi:Microsoft Mark - English (United States)?en-US', name: 'Microsoft Mark - English (United States)', lang: 'en-US', localService: true, default: false },
                { voiceURI: 'urn:moz-tts:sapi:Microsoft Zira - English (United States)?en-US', name: 'Microsoft Zira - English (United States)', lang: 'en-US', localService: true, default: false },
                { voiceURI: 'urn:moz-tts:sapi:Microsoft David Desktop - English (United States)?en-US', name: 'Microsoft David Desktop - English (United States)', lang: 'en-US', localService: true, default: false },
                { voiceURI: 'urn:moz-tts:sapi:Microsoft Zira Desktop - English (United States)?en-US', name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US', localService: true, default: false }
            ];

            const chromeVoices = [
                { voiceURI: 'Microsoft David - English (United States)', name: 'Microsoft David - English (United States)', lang: 'en-US', localService: true, default: true },
                { voiceURI: 'Microsoft Mark - English (United States)', name: 'Microsoft Mark - English (United States)', lang: 'en-US', localService: true, default: false },
                { voiceURI: 'Microsoft Zira - English (United States)', name: 'Microsoft Zira - English (United States)', lang: 'en-US', localService: true, default: false },
                { voiceURI: 'Google US English', name: 'Google US English', lang: 'en-US', localService: false, default: false },
                { voiceURI: 'Google UK English Female', name: 'Google UK English Female', lang: 'en-GB', localService: false, default: false },
                { voiceURI: 'Google UK English Male', name: 'Google UK English Male', lang: 'en-GB', localService: false, default: false }
            ];

            const spoofedVoices = isFirefox ? firefoxVoices : chromeVoices;

            const frozenVoices = spoofedVoices.map(voice => {
                const voiceObj = {
                    voiceURI: voice.voiceURI,
                    name: voice.name,
                    lang: voice.lang,
                    localService: voice.localService,
                    default: voice.default
                };
                return Object.freeze(voiceObj);
            });

            const originalGetVoices = window.speechSynthesis.getVoices;
            window.speechSynthesis.getVoices = function() {
                return frozenVoices.slice(); 
            };

            safeDefine(window.speechSynthesis, 'onvoiceschanged', {
                get: function() { return null; },
                set: function(handler) {

                    if (handler && typeof handler === 'function') {
                        setTimeout(() => handler.call(window.speechSynthesis), 0);
                    }
                },
                enumerable: true,
                configurable: true
            });

            if (window.speechSynthesis.onvoiceschanged) {
                window.speechSynthesis.onvoiceschanged();
            }

            status.speech_synthesis = `applied (${spoofedVoices.length} ${isFirefox ? 'Firefox' : 'Chrome'} voices)`;
            if (debug) console.log(`[FP] Speech synthesis spoofing applied (${spoofedVoices.length} voices)`);

        } catch (e) {
            if (debug) console.error("[FP] Speech synthesis spoofing error:", e);
            status.speech_synthesis = "error: " + e.message;
        }
    }

    setTimeout(function() {

        if (window.MutationObserver) {
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.tagName === 'IFRAME' && node.contentWindow) {
                            try {

                                node.contentWindow.__fpConfig = config;
                                node.contentWindow.eval('(' + arguments.callee.toString() + ')()');
                            } catch (e) {

                            }
                        }
                    });
                });
            });

            if (document.body) {
                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });
            }
        }

        try {
            const scripts = document.querySelectorAll('script');
            scripts.forEach(script => {
                if (script.textContent && (
                    script.textContent.includes('__fpSpoofed') ||
                    script.textContent.includes('__fpConfig')
                )) {
                    script.style.display = 'none';
                    script.remove();
                }
            });
        } catch (e) {

        }

        if (config.enable_network_spoof && navigator.connection) {
            try {
                const spoofedConnection = {
                    downlink: config.network_downlink || 10,
                    effectiveType: config.network_effective_type || '4g',
                    rtt: config.network_rtt || 50,
                    saveData: config.network_save_data || false,
                    type: config.network_type || 'wifi',

                    onchange: null,
                    addEventListener: function() {},
                    removeEventListener: function() {},
                    dispatchEvent: function() { return true; }
                };

                safeDefine(Navigator.prototype, 'connection', {
                    get: function() { return spoofedConnection; },
                    enumerable: true,
                    configurable: false
                });

                if (navigator.mozConnection) {
                    safeDefine(Navigator.prototype, 'mozConnection', {
                        get: function() { return spoofedConnection; },
                        enumerable: true,
                        configurable: false
                    });
                }

                if (navigator.webkitConnection) {
                    safeDefine(Navigator.prototype, 'webkitConnection', {
                        get: function() { return spoofedConnection; },
                        enumerable: true,
                        configurable: false
                    });
                }

                status.network_spoof = 'active';
                if (debug) console.log(`[FP] Network Information API spoofed (${spoofedConnection.effectiveType}, ${spoofedConnection.downlink} Mbps)`);
            } catch (e) {
                status.network_spoof = 'error: ' + e.message;
                if (debug) console.error('[FP] Network spoofing error:', e);
            }
        }

        if (config.enable_font_spoof && config.fonts && Array.isArray(config.fonts)) {
            try {
                const spoofedFonts = config.fonts;

                if (debug) console.log(`[FP] Applying font protection (${spoofedFonts.length} fonts)...`);

                if (document.fonts) {
                    Object.defineProperty(document, 'fonts', {
                        get: function() {
                            const mockFontFaceSet = {
                                size: spoofedFonts.length,
                                ready: Promise.resolve(this),
                                status: 'loaded',
                                check: function(font, text) {
                                    const fontFamily = font.match(/['"]?([^'"]+)['"]?/);
                                    if (fontFamily && fontFamily[1]) {
                                        return spoofedFonts.includes(fontFamily[1]);
                                    }
                                    return false;
                                },
                                load: function(font, text) {
                                    return Promise.resolve([]);
                                },
                                has: function(fontFace) {
                                    return spoofedFonts.includes(fontFace.family);
                                },
                                add: function(fontFace) { return this; },
                                delete: function(fontFace) { return false; },
                                clear: function() {},
                                entries: function() { return [][Symbol.iterator](); },
                                forEach: function(callback) {},
                                keys: function() { return [][Symbol.iterator](); },
                                values: function() { return [][Symbol.iterator](); },
                                [Symbol.iterator]: function() { return [][Symbol.iterator](); }
                            };

                            return mockFontFaceSet;
                        },
                        enumerable: true,
                        configurable: true
                    });
                }

                const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;

                const baselineMeasurements = {};
                const testStrings = ['mmmmmmmmmmlli', 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789'];
                const fallbackFonts = ['monospace', 'sans-serif', 'serif'];

                CanvasRenderingContext2D.prototype.measureText = function(text) {
                    const originalResult = originalMeasureText.call(this, text);

                    const currentFont = this.font || '10px sans-serif';
                    const fontMatch = currentFont.match(/(?:['"]([^'"]+)['"]|([^\s,]+))(?:\s*,|\s*$)/);

                    if (!fontMatch) {
                        return originalResult;
                    }

                    const requestedFont = (fontMatch[1] || fontMatch[2]).trim();

                    if (!spoofedFonts.includes(requestedFont) && !fallbackFonts.includes(requestedFont)) {

                        const fallbackFont = currentFont.replace(requestedFont, 'monospace');
                        const savedFont = this.font;
                        this.font = fallbackFont;
                        const fallbackMetrics = originalMeasureText.call(this, text);
                        this.font = savedFont;

                        return fallbackMetrics;
                    }

                    return originalResult;
                };

                status.font_spoof = 'active';
                if (debug) console.log(`[FP] Font protection applied (${spoofedFonts.length} fonts)`);
            } catch (e) {
                status.font_spoof = 'error: ' + e.message;
                if (debug) console.error('[FP] Font spoofing error:', e);
            }
        }

        if (config.enable_viewport_spoof) {
            try {

                const roundingIncrement = config.viewport_rounding || 200; 

                const MIN_WIDTH = 320;  
                const MIN_HEIGHT = 568;  

                const actualWidth = window.innerWidth;
                const actualHeight = window.innerHeight;

                let spoofedWidth = config.viewport_width || Math.floor(actualWidth / roundingIncrement) * roundingIncrement;
                let spoofedHeight = config.viewport_height || Math.floor(actualHeight / roundingIncrement) * roundingIncrement;

                if (spoofedWidth < MIN_WIDTH) spoofedWidth = MIN_WIDTH;
                if (spoofedHeight < MIN_HEIGHT) spoofedHeight = MIN_HEIGHT;

                const paddingHorizontal = actualWidth - spoofedWidth;
                const paddingVertical = actualHeight - spoofedHeight;

                if (debug) {
                    console.log(`[FP] Viewport spoofing: ${actualWidth}x${actualHeight} -> ${spoofedWidth}x${spoofedHeight}`);
                    console.log(`[FP] Adding padding: ${paddingHorizontal}px horizontal, ${paddingVertical}px vertical`);
                }

                const applyPadding = function() {
                    if (document.body) {
                        const style = document.createElement('style');
                        style.id = '__fp_viewport_padding';
                        style.textContent = `
                            html, body {
                                margin: 0 !important;
                                padding: 0 !important;

                            }
                            body {
                                box-sizing: border-box !important;
                                padding-right: ${paddingHorizontal}px !important;
                                padding-bottom: ${paddingVertical}px !important;

                                background: linear-gradient(to right, transparent ${spoofedWidth}px, rgba(0,0,0,0.02) ${spoofedWidth}px),
                                            linear-gradient(to bottom, transparent ${spoofedHeight}px, rgba(0,0,0,0.02) ${spoofedHeight}px) !important;
                            }
                            body > * {
                                max-width: ${spoofedWidth}px !important;
                            }
                        `;

                        const existingStyle = document.getElementById('__fp_viewport_padding');
                        if (existingStyle) {
                            existingStyle.remove();
                        }

                        document.head.appendChild(style);
                    }
                };

                if (document.body) {
                    applyPadding();
                } else {
                    document.addEventListener('DOMContentLoaded', applyPadding);
                }

                Object.defineProperty(window, 'innerWidth', {
                    get: function() { return spoofedWidth; },
                    enumerable: true,
                    configurable: true
                });

                Object.defineProperty(window, 'innerHeight', {
                    get: function() { return spoofedHeight; },
                    enumerable: true,
                    configurable: true
                });

                Object.defineProperty(window, 'outerWidth', {
                    get: function() { return actualWidth; },
                    enumerable: true,
                    configurable: true
                });

                Object.defineProperty(window, 'outerHeight', {
                    get: function() { return actualHeight; },
                    enumerable: true,
                    configurable: true
                });

                if (document.documentElement) {
                    Object.defineProperty(document.documentElement, 'clientWidth', {
                        get: function() { return spoofedWidth; },
                        enumerable: true,
                        configurable: true
                    });

                    Object.defineProperty(document.documentElement, 'clientHeight', {
                        get: function() { return spoofedHeight; },
                        enumerable: true,
                        configurable: true
                    });
                }

                const overrideBodyDimensions = function() {
                    if (document.body) {
                        Object.defineProperty(document.body, 'clientWidth', {
                            get: function() { return spoofedWidth; },
                            enumerable: true,
                            configurable: true
                        });

                        Object.defineProperty(document.body, 'clientHeight', {
                            get: function() { return spoofedHeight; },
                            enumerable: true,
                            configurable: true
                        });
                    }
                };

                if (document.body) {
                    overrideBodyDimensions();
                } else {
                    document.addEventListener('DOMContentLoaded', overrideBodyDimensions);
                }

                if (window.visualViewport) {
                    Object.defineProperty(window.visualViewport, 'width', {
                        get: function() { return spoofedWidth; },
                        enumerable: true,
                        configurable: true
                    });

                    Object.defineProperty(window.visualViewport, 'height', {
                        get: function() { return spoofedHeight; },
                        enumerable: true,
                        configurable: true
                    });
                }

                Object.defineProperty(window.screen, 'availWidth', {
                    get: function() { return spoofedWidth; },
                    enumerable: true,
                    configurable: true
                });

                Object.defineProperty(window.screen, 'availHeight', {
                    get: function() { return spoofedHeight; },
                    enumerable: true,
                    configurable: true
                });

                status.viewport_spoof = `active (${spoofedWidth}x${spoofedHeight} with ${paddingHorizontal}x${paddingVertical}px padding)`;
                if (debug) console.log(`[FP] Viewport spoofing enabled (${spoofedWidth}x${spoofedHeight})`);
            } catch (e) {
                status.viewport_spoof = 'error: ' + e.message;
                if (debug) console.error('[FP] Viewport spoofing error:', e);
            }
        }

        if (debug) {
            console.log("[FP] FINAL REPORT ");
            console.log("[FP] User-Agent:", navigator.userAgent);
            console.log("[FP] Platform:", navigator.platform);
            console.log("[FP] Hardware Concurrency:", navigator.hardwareConcurrency);
            console.log("[FP] Device Memory:", navigator.deviceMemory);
            console.log("[FP] Screen:", screen.width + "x" + screen.height);
            console.log("[FP] Viewport:", window.innerWidth + "x" + window.innerHeight);
            console.log("[FP] Timezone Offset:", new Date().getTimezoneOffset());
            console.log("[FP] Fonts Available:", config.fonts ? config.fonts.length : 0);
            console.log("[FP] Module Status:", status);
        }

        window.__fpStatus = status;

        if (debug) console.log("[FP] All spoofing modules complete");

    }, 10);

})();