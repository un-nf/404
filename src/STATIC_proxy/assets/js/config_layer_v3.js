/* STATIC Proxy Config Layer v3 (AGPL-3.0) */
;(function staticConfigLayerV3() {
  'use strict';

  if (!window.__static_bootstrap_active) {
    console.error('[STATIC-CONFIG] bootstrap missing, spoof stack degraded');
  }

  if (!window.__static_shim_active) {
    console.error('[STATIC-CONFIG] globals shim missing, spoof stack degraded');
  }

  let parsedConfig = {};
  try {
    let RAW_CONFIG;
    try {
      RAW_CONFIG = ({{config_json}});
    } catch (_) {
      RAW_CONFIG = '{{config_json}}';
    }

    if (typeof RAW_CONFIG === 'string') {
      if (RAW_CONFIG && RAW_CONFIG !== '{{config_json}}') {
        parsedConfig = JSON.parse(RAW_CONFIG);
      }
    } else if (RAW_CONFIG && typeof RAW_CONFIG === 'object') {
      parsedConfig = RAW_CONFIG;
    }
  } catch (err) {
    console.error('[STATIC-CONFIG] failed to parse config json:', err && err.message ? err.message : err);
    parsedConfig = {};
  }

  function selectFingerprint(config) {
    if (
      config &&
      typeof config === 'object' &&
      config.fingerprint &&
      typeof config.fingerprint === 'object'
    ) {
      return config.fingerprint;
    }
    return config;
  }

  const fingerprintConfig = selectFingerprint(parsedConfig) || {};

  if (fingerprintConfig && fingerprintConfig.enable_canvas_guard === false) {
    window.__STATIC_DISABLE_CANVAS_GUARD = true;
  } else if (window.__STATIC_DISABLE_CANVAS_GUARD) {
    try {
      delete window.__STATIC_DISABLE_CANVAS_GUARD;
    } catch (_) {
      window.__STATIC_DISABLE_CANVAS_GUARD = undefined;
    }
  }

  function pickField(key) {
    if (fingerprintConfig && Object.prototype.hasOwnProperty.call(fingerprintConfig, key)) {
      return fingerprintConfig[key];
    }
    if (parsedConfig && Object.prototype.hasOwnProperty.call(parsedConfig, key)) {
      return parsedConfig[key];
    }
    return undefined;
  }

  window.__STATIC_CONFIG__ = parsedConfig;
  window.__STATIC_FINGERPRINT__ = fingerprintConfig;
  window.__fpConfig = fingerprintConfig;

  const required = [
    'user_agent',
    'platform',
    'browser_type',
    'canvas_hash',
    'webgl_vendor',
    'webgl_renderer'
  ];

  const missing = required.filter((key) => {
    const value = pickField(key);
    return value === undefined || value === '';
  });

  if (missing.length > 0) {
    console.error('[STATIC-CONFIG] missing required fields:', missing);
  }

  const ua = pickField('user_agent') || '';
  const platform = pickField('platform') || '';
  const vendor = pickField('vendor') || '';
  const browserType = pickField('browser_type') || pickField('browserType') || '';

  let coherenceErrors = 0;

  if (ua.includes('Windows') && !platform.includes('Win')) {
    console.error('[STATIC-CONFIG] windows ua but non-windows platform');
    coherenceErrors += 1;
  }

  if (ua.includes('Mac OS X') && platform !== 'MacIntel') {
    console.error('[STATIC-CONFIG] mac ua but platform mismatch');
    coherenceErrors += 1;
  }

  if (ua.includes('Linux') && !platform.includes('Linux')) {
    console.error('[STATIC-CONFIG] linux ua but platform mismatch');
    coherenceErrors += 1;
  }

  if (
    (ua.includes('Chrome') || ua.includes('Chromium') || ua.includes('Edg')) &&
    browserType === 'chrome' &&
    vendor !== 'Google Inc.'
  ) {
    console.error('[STATIC-CONFIG] chrome profile must expose Google Inc vendor');
    coherenceErrors += 1;
  }

  if (ua.includes('Firefox') && browserType === 'firefox' && vendor !== '') {
    console.error('[STATIC-CONFIG] firefox profile must expose blank vendor');
    coherenceErrors += 1;
  }

  if (browserType === 'firefox' && pickField('sec_ch_ua')) {
    console.warn('[STATIC-CONFIG] firefox profile has client hints; ignored');
  }

  const screenResolution = pickField('screen_resolution');
  if (screenResolution && !/^\d+x\d+$/.test(String(screenResolution))) {
    console.error('[STATIC-CONFIG] invalid screen_resolution format:', screenResolution);
    coherenceErrors += 1;
  }

  if (coherenceErrors > 0) {
    console.error(`[STATIC-CONFIG] ${coherenceErrors} profile coherence errors detected`);
  }

  const debugFlag = pickField('debug') ?? parsedConfig.debug;
  if (debugFlag) {
    console.log('[STATIC-CONFIG] profile loaded:', pickField('name') || parsedConfig.name || 'unknown');
    console.log('[STATIC-CONFIG] browser:', browserType || 'unknown', pickField('browser_version') || 'unknown');
    console.log('[STATIC-CONFIG] os:', pickField('os') || 'unknown');
  }

  window.__static_config_ready = true;
  window.__static_config_version = '3.0.0';

  console.log('[STATIC-CONFIG] config hydrated');
})();