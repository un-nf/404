/* Config Layer

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
  
  // Validate Bootstrap Loaded (V2)
  
  if (!window.__404_bootstrap_active) {
    console.error('[404] Bootstrap missing - partial protection only');
  }
  
  // Validate Globals Shim Loaded (V2)
  
  if (!window.__404_shim_active) {
    console.error('[404] Globals shim missing - partial protection only');
  }
  
  // Load Configuration
  
  // This will be replaced by js_injector.py with actual JSON
  window.__fpConfig = JSON.parse('{{config_json}}');
  
  // Validate Required Fields
  
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
    console.error('[404] Missing required config fields:', missing);
  }
  
  // Coherence Validation
  
  const ua = window.__fpConfig.user_agent || '';
  const platform = window.__fpConfig.platform || '';
  const vendor = window.__fpConfig.vendor || '';
  const browserType = window.__fpConfig.browser_type || '';
  
  let coherenceErrors = 0;
  
  // Check: Windows UA must have Win32/Win64 platform
  if (ua.includes('Windows') && !platform.includes('Win')) {
    console.error('[404] Profile mismatch: Windows UA with non-Windows platform');
    coherenceErrors++;
  }
  
  // Check: Mac UA must have MacIntel platform
  if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
    console.error('[404] Profile mismatch: Mac UA with wrong platform');
    coherenceErrors++;
  }
  
  // Check: Linux UA must have Linux platform
  if (ua.includes('Linux') && !platform.includes('Linux')) {
    console.error('[404] Profile mismatch: Linux UA with wrong platform');
    coherenceErrors++;
  }
  
  // Check: Chrome/Chromium UA must have Google Inc. vendor
  if ((ua.includes('Chrome') || ua.includes('Chromium') || ua.includes('Edg')) && 
      browserType === 'chrome' && vendor !== 'Google Inc.') {
    console.error('[404] Profile mismatch: Chrome UA with wrong vendor');
    coherenceErrors++;
  }
  
  // Check: Firefox UA must have empty vendor
  if (ua.includes('Firefox') && browserType === 'firefox' && vendor !== '') {
    console.error('[404] Profile mismatch: Firefox UA with non-empty vendor');
    coherenceErrors++;
  }
  
  // Check: Firefox should not have Client Hints in config
  if (browserType === 'firefox' && window.__fpConfig.sec_ch_ua) {
    console.warn('[404] Firefox profile has Client Hints (ignored)');
  }
  
  // Check: Screen resolution format
  if (window.__fpConfig.screen_resolution) {
    const screenMatch = window.__fpConfig.screen_resolution.match(/^(\d+)x(\d+)$/);
    if (!screenMatch) {
      console.error('[404] Invalid screen resolution format:', window.__fpConfig.screen_resolution);
      coherenceErrors++;
    }
  }
  
  if (coherenceErrors > 0) {
    console.error('[404] ${coherenceErrors} profile coherence errors detected');
  }
  
  // Debug Logging (if enabled)
  
  if (window.__fpConfig.debug) {
    console.log('[404] Debug mode enabled');
    console.log('[404] Profile:', window.__fpConfig.name || 'Unknown');
    console.log('[404] Browser:', browserType, window.__fpConfig.browser_version || 'Unknown');
    console.log('[404] OS:', window.__fpConfig.os || 'Unknown');
  }
  
  // Ready
  
  window.__404_config_ready = true;
  window.__404_config_version = '2.0.0';
  
  console.log('[404] Config loaded:', window.__fpConfig.name || 'Unknown');
  
  // Config object remains in global scope for runtime spoofing access
  // Version flags will be cleaned up by fingerprint_spoof_v2.js after init
  
})();