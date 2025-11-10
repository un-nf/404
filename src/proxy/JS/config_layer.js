/* Config ayer

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
  
  console.log('[404-CONFIG] Loading configuration...');
  
  // =============
  // Validate Preflight Loaded
  // =============
  
  if (!window.__404_preflight_ready) {
    console.error('[404-CONFIG] CRITICAL: Preflight not loaded!');
    console.error('[404-CONFIG] Detection resistance will be REDUCED');
    console.error('[404-CONFIG] Creating minimal fallback helpers...');
    
    // Minimal fallback (degraded functionality)
    // This allows spoofing to work, but without toString() protection
    window.__404_defineProperty = function(obj, prop, val) {
      try {
        Object.defineProperty(obj, prop, {
          get: function() { return val; },
          enumerable: true,
          configurable: true
        });
      } catch (e) {
        console.error('[404-CONFIG] Fallback defineProperty failed:', e);
      }
    };
    
    window.__404_freeze = function(obj) {
      try {
        return Object.freeze(obj);
      } catch (e) {
        return obj;
      }
    };
    
    console.warn('[404-CONFIG] Fallback helpers created (limited protection)');
  } else {
    console.log('[404-CONFIG] Preflight layer detected');
  }
  
  // =============
  // Load Configuration
  // =============
  
  // This will be replaced by js_injector.py with actual JSON
  window.__fpConfig = JSON.parse('{{config_json}}');
  
  console.log('[404-CONFIG] Configuration loaded');
  
  // =============
  // Validate Required Fields
  // =============
  
  const required = [
    'user_agent',
    'platform',
    'canvas_hash',
    'webgl_vendor',
    'webgl_renderer',
    'browser_type'
  ];
  
  const missing = required.filter(field => {
    return !window.__fpConfig[field] || window.__fpConfig[field] === '';
  });
  
  if (missing.length > 0) {
    console.error('[404-CONFIG] ERROR: Missing required fields:', missing);
    console.error('[404-CONFIG] Spoofing will be incomplete!');
    console.error('[404-CONFIG] This may cause fingerprint detection');
  } else {
    console.log('[404-CONFIG] All required fields present');
  }
  
  // =============
  // Coherence Validation
  // =============
  
  const ua = window.__fpConfig.user_agent || '';
  const platform = window.__fpConfig.platform || '';
  const vendor = window.__fpConfig.vendor || '';
  const browserType = window.__fpConfig.browser_type || '';
  
  let coherenceErrors = 0;
  
  // Check: Windows UA must have Win32/Win64 platform
  if (ua.includes('Windows') && !platform.includes('Win')) {
    console.error('[404-CONFIG] INCOHERENCE: Windows UA but non-Windows platform!');
    console.error('[404-CONFIG] UA:', ua.substring(0, 60) + '...');
    console.error('[404-CONFIG] Platform:', platform);
    coherenceErrors++;
  }
  
  // Check: Mac UA must have MacIntel platform
  if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
    console.error('[404-CONFIG] INCOHERENCE: Mac UA but non-Mac platform!');
    console.error('[404-CONFIG] UA:', ua.substring(0, 60) + '...');
    console.error('[404-CONFIG] Platform:', platform);
    coherenceErrors++;
  }
  
  // Check: Linux UA must have Linux platform
  if (ua.includes('Linux') && !platform.includes('Linux')) {
    console.error('[404-CONFIG] INCOHERENCE: Linux UA but non-Linux platform!');
    console.error('[404-CONFIG] UA:', ua.substring(0, 60) + '...');
    console.error('[404-CONFIG] Platform:', platform);
    coherenceErrors++;
  }
  
  // Check: Chrome/Chromium UA must have Google Inc. vendor
  if ((ua.includes('Chrome') || ua.includes('Chromium') || ua.includes('Edg')) && 
      browserType === 'chrome' && vendor !== 'Google Inc.') {
    console.error('[404-CONFIG] INCOHERENCE: Chrome UA but wrong vendor!');
    console.error('[404-CONFIG] UA:', ua.substring(0, 60) + '...');
    console.error('[404-CONFIG] Vendor:', vendor, '(expected: Google Inc.)');
    coherenceErrors++;
  }
  
  // Check: Firefox UA must have empty vendor
  if (ua.includes('Firefox') && browserType === 'firefox' && vendor !== '') {
    console.error('[404-CONFIG] INCOHERENCE: Firefox UA but non-empty vendor!');
    console.error('[404-CONFIG] UA:', ua.substring(0, 60) + '...');
    console.error('[404-CONFIG] Vendor:', vendor, '(expected: empty string)');
    coherenceErrors++;
  }
  
  // Check: Firefox should not have Client Hints in config
  if (browserType === 'firefox' && window.__fpConfig.sec_ch_ua) {
    console.warn('[404-CONFIG] WARNING: Firefox profile has Client Hints (will be ignored)');
  }
  
  // Check: Screen resolution format
  if (window.__fpConfig.screen_resolution) {
    const screenMatch = window.__fpConfig.screen_resolution.match(/^(\d+)x(\d+)$/);
    if (!screenMatch) {
      console.error('[404-CONFIG] INCOHERENCE: Invalid screen resolution format!');
      console.error('[404-CONFIG] Got:', window.__fpConfig.screen_resolution);
      console.error('[404-CONFIG] Expected: WIDTHxHEIGHT (e.g., 1920x1080)');
      coherenceErrors++;
    }
  }
  
  if (coherenceErrors === 0) {
    console.log('[404-CONFIG] Profiles validated');
  } else {
    console.error(`[404-CONFIG] ${coherenceErrors} coherence error(s) detected`);
    console.error('[404-CONFIG] This WILL cause fingerprint detection!');
  }
  
  // =============
  // Debug Logging (if enabled)
  // =============
  
  if (window.__fpConfig.debug) {
    console.log('[404-CONFIG] ========== DEBUG INFO ==========');
    console.log('[404-CONFIG] Profile Name:', window.__fpConfig.name || 'Unknown');
    console.log('[404-CONFIG] Browser Type:', browserType);
    console.log('[404-CONFIG] Browser Version:', window.__fpConfig.browser_version || 'Unknown');
    console.log('[404-CONFIG] OS:', window.__fpConfig.os || 'Unknown');
    console.log('[404-CONFIG] User-Agent:', ua.substring(0, 80) + '...');
    console.log('[404-CONFIG] Platform:', platform);
    console.log('[404-CONFIG] Vendor:', vendor || '(empty)');
    console.log('[404-CONFIG] Hardware Concurrency:', window.__fpConfig.hardware_concurrency);
    console.log('[404-CONFIG] Device Memory:', window.__fpConfig.device_memory);
    console.log('[404-CONFIG] Screen Resolution:', window.__fpConfig.screen_resolution);
    console.log('[404-CONFIG] Canvas Hash:', window.__fpConfig.canvas_hash);
    console.log('[404-CONFIG] WebGL Vendor:', window.__fpConfig.webgl_vendor);
    console.log('[404-CONFIG] WebGL Renderer:', window.__fpConfig.webgl_renderer);
    console.log('[404-CONFIG] Audio Hash:', window.__fpConfig.audio_hash);
    console.log('[404-CONFIG] =====');
  }
  
  // =============
  // Ready
  // =============
  
  window.__404_config_ready = true;
  window.__404_config_version = '1.0.0';
  
  console.log('[404-CONFIG] ✅ Configuration ready for spoofing layer');
  
  // Config object stays in global scope for spoofing layer to access
  // It will be cleaned up by sandbox layer after spoofing completes
  
})();
