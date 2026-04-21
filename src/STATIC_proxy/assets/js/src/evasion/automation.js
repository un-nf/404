import { getFingerprint } from '../core/config.js'
import { defaultUaDataBrands, resolveBrowserFamily, resolveBrowserVariant } from '../core/browser.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

const AUTOMATION_GLOBALS = [
  '__webdriver_script_fn',
  '__webdriver_script_func',
  '__webdriver_script_function',
  '__driver_evaluate',
  '__webdriver_evaluate',
  '__selenium_evaluate',
  '__fxdriver_evaluate',
  '__driver_unwrapped',
  '__webdriver_unwrapped',
  '__selenium_unwrapped',
  '__fxdriver_unwrapped',
  '_phantom',
  '__nightmare',
  'callPhantom',
  '_selenium',
  'calledSelenium',
  'callSelenium',
  '_Selenium_IDE_Recorder',
  '__webdriverFunc',
  '__lastWatirAlert',
  '__lastWatirConfirm',
  '__lastWatirPrompt',
  '_WEBDRIVER_ELEM_CACHE',
  'ChromeDriverw',
  '__playwright__binding__',
  '__pwInitScripts',
  '$chrome_asyncScriptInfo',
  '__$webdriverAsyncExecutor',
  'domAutomation',
  'domAutomationController',
]

const CHROMEDRIVER_GLOBAL_PATTERNS = [
  /^cdc_[a-zA-Z0-9]+_(Array|Promise|Symbol|JSON|Window)$/,
  /^\$cdc_[a-zA-Z0-9]+_$/,
]

const AUTOMATION_ELEMENT_KEYS = ['selenium', 'webdriver', 'driver']

function matchesChromedriverPattern(key) {
  return CHROMEDRIVER_GLOBAL_PATTERNS.some((pattern) => pattern.test(key))
}

function suppressGlobalProperty(target, name) {
  try {
    Reflect.deleteProperty(target, name)
  } catch {
    // ignore
  }

  if (!(name in target)) {
    return
  }

  try {
    Object.defineProperty(target, name, {
      get: markNativeCode(function propertyGetter() {
        return undefined
      }, name),
      configurable: true,
      enumerable: false,
    })
  } catch {
    // ignore
  }
}

function cleanupAutomationGlobals(target) {
  for (const key of AUTOMATION_GLOBALS) {
    suppressGlobalProperty(target, key)
  }

  for (const key of Object.getOwnPropertyNames(target)) {
    if (matchesChromedriverPattern(key)) {
      suppressGlobalProperty(target, key)
    }
  }
}

function suppressElementProperty(target, name) {
  if (!target) {
    return
  }

  try {
    Reflect.deleteProperty(target, name)
  } catch {
    // ignore
  }

  if (!(name in target)) {
    return
  }

  try {
    Object.defineProperty(target, name, {
      get: markNativeCode(function propertyGetter() {
        return undefined
      }, name),
      configurable: true,
      enumerable: false,
    })
  } catch {
    // ignore
  }
}

function cleanupDocumentAutomationMarkers(doc) {
  if (!doc) {
    return
  }

  cleanupAutomationGlobals(doc)

  const root = doc.documentElement
  if (!root) {
    return
  }

  for (const key of AUTOMATION_ELEMENT_KEYS) {
    try {
      root.removeAttribute(key)
    } catch {
      // ignore
    }
    suppressElementProperty(root, key)
  }

  for (const key of Object.keys(root)) {
    if (AUTOMATION_ELEMENT_KEYS.includes(key) || matchesChromedriverPattern(key)) {
      suppressElementProperty(root, key)
    }
  }
}

function definePrototypeGetter(prototype, name, getter, defaultEnumerable = true) {
  const descriptor = Object.getOwnPropertyDescriptor(prototype, name)
  Object.defineProperty(prototype, name, {
    get: markNativeCode(getter, name),
    configurable: descriptor?.configurable ?? true,
    enumerable: descriptor?.enumerable ?? defaultEnumerable,
  })
}

function definePrototypeValue(prototype, name, value, defaultEnumerable = false) {
  const descriptor = Object.getOwnPropertyDescriptor(prototype, name)
  Object.defineProperty(prototype, name, {
    value: markNativeCode(value, name),
    configurable: descriptor?.configurable ?? true,
    writable: descriptor?.writable ?? true,
    enumerable: descriptor?.enumerable ?? defaultEnumerable,
  })
}

function installDocumentAutomationObserver(doc) {
  const root = doc?.documentElement
  if (!root || typeof MutationObserver !== 'function') {
    return
  }

  const observer = new MutationObserver(() => {
    cleanupDocumentAutomationMarkers(doc)
  })

  observer.observe(root, {
    attributes: true,
    attributeFilter: AUTOMATION_ELEMENT_KEYS,
  })
}

function buildWorkerUserAgentDataConfig(fingerprint) {
  const uaData = fingerprint.ua_data || {}
  const brands = uaData.brands || defaultUaDataBrands(fingerprint)
  const mobile = uaData.mobile || false
  const platform = uaData.platform || fingerprint.sec_ch_ua_platform || fingerprint.platform || ''

  return {
    architecture: uaData.architecture || 'x86',
    bitness: uaData.bitness || '64',
    brands,
    fullVersionList: uaData.full_version_list || brands,
    mobile,
    model: uaData.model || '',
    platform,
    platformVersion: uaData.platform_version || '10.0.0',
    uaFullVersion: uaData.ua_full_version || fingerprint.browser_version || '',
  }
}

function buildWorkerBootstrapSource(originalUrl, fingerprint) {
  const browserFamily = resolveBrowserFamily(fingerprint)
  const browserVariant = resolveBrowserVariant(fingerprint)
  const config = {
    browserFamily,
    browserVariant,
    userAgent: fingerprint.user_agent || '',
    platform: fingerprint.platform || '',
    vendor: fingerprint.vendor ?? '',
    productSub: fingerprint.productSub ?? '20030107',
    oscpu: fingerprint.oscpu || '',
    buildID: fingerprint.buildID || '',
    hardwareConcurrency: Number(fingerprint.hardware_concurrency),
    maxTouchPoints: Number(fingerprint.max_touch_points),
    language: Array.isArray(fingerprint.languages) ? fingerprint.languages[0] : (fingerprint.language || 'en-US'),
    languages: Array.isArray(fingerprint.languages)
      ? fingerprint.languages.slice()
      : String(fingerprint.language || 'en-US').split(',').map((value) => value.trim()).filter(Boolean),
    pdfViewerEnabled: fingerprint.pdf_viewer_enabled ?? false,
    uaData: buildWorkerUserAgentDataConfig(fingerprint),
    vendorFlavors: Array.isArray(fingerprint.vendor_flavors) ? fingerprint.vendor_flavors.slice() : [],
  }

  // Classic workers only — module workers are never passed through this path.
  // importScripts is the correct loader for classic workers.
  const loader = `importScripts(${JSON.stringify(originalUrl)});`

  return `(() => {
  const config = ${JSON.stringify(config)};
  const automationGlobals = ${JSON.stringify(AUTOMATION_GLOBALS)};
  const chromedriverPatterns = [
    /^cdc_[a-zA-Z0-9]+_(Array|Promise|Symbol|JSON|Window)$/,
    /^\$cdc_[a-zA-Z0-9]+_$/,
  ];
  const defineGetter = (target, name, value) => {
    try {
      Object.defineProperty(target, name, {
        get() {
          return value;
        },
        configurable: true,
        enumerable: false,
      });
    } catch {
      // ignore
    }
  };
  const matchesChromedriverPattern = (key) => chromedriverPatterns.some((pattern) => pattern.test(key));
  const suppressProperty = (target, name) => {
    try {
      Reflect.deleteProperty(target, name);
    } catch {
      // ignore
    }

    if (!(name in target)) {
      return;
    }

    defineGetter(target, name, undefined);
  };
  const cleanup = (target) => {
    for (const key of automationGlobals) {
      suppressProperty(target, key);
    }
    for (const key of Object.getOwnPropertyNames(target)) {
      if (matchesChromedriverPattern(key)) {
        suppressProperty(target, key);
      }
    }
  };
  const navigatorTarget = self.navigator;
  const navigatorProto = navigatorTarget ? Object.getPrototypeOf(navigatorTarget) : null;
  if (navigatorProto) {
    defineGetter(navigatorProto, 'webdriver', false);
    if (config.userAgent) defineGetter(navigatorProto, 'userAgent', config.userAgent);
    if (config.platform) defineGetter(navigatorProto, 'platform', config.platform);
    if (typeof config.vendor === 'string') defineGetter(navigatorProto, 'vendor', config.vendor);
    if (config.productSub) defineGetter(navigatorProto, 'productSub', config.productSub);
    if (config.language) defineGetter(navigatorProto, 'language', config.language);
    if (Array.isArray(config.languages)) defineGetter(navigatorProto, 'languages', Object.freeze(config.languages.slice()));
    if (Number.isFinite(config.hardwareConcurrency)) defineGetter(navigatorProto, 'hardwareConcurrency', config.hardwareConcurrency);
    if (Number.isFinite(config.maxTouchPoints)) defineGetter(navigatorProto, 'maxTouchPoints', config.maxTouchPoints);
    if (typeof config.pdfViewerEnabled === 'boolean') defineGetter(navigatorProto, 'pdfViewerEnabled', config.pdfViewerEnabled);
    if (config.oscpu) defineGetter(navigatorProto, 'oscpu', config.oscpu);
    if (config.buildID) defineGetter(navigatorProto, 'buildID', config.buildID);
    if (config.browserFamily === 'chromium-like') {
      defineGetter(navigatorProto, 'vendorFlavors', Object.freeze(Array.isArray(config.vendorFlavors) ? config.vendorFlavors.slice() : []));
      defineGetter(navigatorProto, 'userAgentData', Object.freeze({
        brands: config.uaData.brands,
        mobile: config.uaData.mobile,
        platform: config.uaData.platform,
        async getHighEntropyValues(hints) {
          const values = {
            architecture: config.uaData.architecture,
            bitness: config.uaData.bitness,
            brands: config.uaData.brands,
            fullVersionList: config.uaData.fullVersionList,
            mobile: config.uaData.mobile,
            model: config.uaData.model,
            platform: config.uaData.platform,
            platformVersion: config.uaData.platformVersion,
            uaFullVersion: config.uaData.uaFullVersion,
          };
          const result = {};
          for (const hint of hints || []) {
            if (Object.prototype.hasOwnProperty.call(values, hint)) {
              result[hint] = values[hint];
            }
          }
          return result;
        },
        toJSON() {
          return {
            brands: config.uaData.brands,
            mobile: config.uaData.mobile,
            platform: config.uaData.platform,
          };
        },
      }));
    }
  }
  cleanup(self);
  ${loader}
})();`
}

function isModuleWorker(options) {
  return typeof options === 'object' && options !== null && options.type === 'module'
}

function scheduleBlobUrlRevoke(blobUrl) {
  if (!blobUrl) {
    return
  }

  setTimeout(() => {
    try {
      URL.revokeObjectURL(blobUrl)
    } catch {
      // ignore
    }
  }, 60_000)
}

function wrapWorkerConstructor(Constructor, fingerprint, workerName) {
  if (typeof Constructor !== 'function' || typeof Blob !== 'function' || typeof URL?.createObjectURL !== 'function') {
    return Constructor
  }

  const wrapped = new Proxy(Constructor, {
    construct(target, args) {
      const [scriptURL, options] = args

      // Module workers load scripts as ES modules, so relative imports inside
      // the worker resolve against the original script URL's origin. Replacing
      // the URL with a blob URL breaks root-relative and relative imports
      // (e.g. import('/worker-bootstrap.js')) because blob: has no meaningful
      // base origin. Pass module workers through untouched.
      if (isModuleWorker(options)) {
        return Reflect.construct(target, args, target)
      }

      const normalizedOptions = typeof options === 'object' && options ? options : {}
      const source = buildWorkerBootstrapSource(String(scriptURL), fingerprint)
      const blobUrl = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }))
      const worker = Reflect.construct(target, [blobUrl, normalizedOptions], target)
      scheduleBlobUrlRevoke(blobUrl)
      return worker
    },
  })

  return markNativeCode(wrapped, workerName)
}

function wrapSharedWorkerConstructor(Constructor, fingerprint) {
  if (typeof Constructor !== 'function' || typeof Blob !== 'function' || typeof URL?.createObjectURL !== 'function') {
    return Constructor
  }

  const wrapped = new Proxy(Constructor, {
    construct(target, args) {
      const [scriptURL, nameOrOptions] = args
      const options = typeof nameOrOptions === 'object' && nameOrOptions ? nameOrOptions : {}

      // Same module worker restriction as wrapWorkerConstructor.
      if (isModuleWorker(options)) {
        return Reflect.construct(target, args, target)
      }

      const source = buildWorkerBootstrapSource(String(scriptURL), fingerprint)
      const blobUrl = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }))
      const worker = Reflect.construct(target, [blobUrl, nameOrOptions], target)
      scheduleBlobUrlRevoke(blobUrl)
      return worker
    },
  })

  return markNativeCode(wrapped, 'SharedWorker')
}

export function installAutomationEvasion() {
  const fingerprint = getFingerprint()
  const browserFamily = resolveBrowserFamily(fingerprint)

  definePrototypeGetter(Navigator.prototype, 'webdriver', function webdriver() {
    return false
  })

  definePrototypeValue(Document.prototype, 'hasFocus', function hasFocus() {
    return true
  })

  definePrototypeGetter(Document.prototype, 'visibilityState', function visibilityState() {
    return 'visible'
  })

  definePrototypeGetter(Document.prototype, 'hidden', function hidden() {
    return false
  })

  if (browserFamily === 'chromium-like') {
    if (!window.chrome) {
      window.chrome = {
        app: { isInstalled: false },
        csi: markNativeCode(function csi() { return {} }, 'csi'),
        loadTimes: markNativeCode(function loadTimes() { return {} }, 'loadTimes'),
        runtime: {},
      }
    }
  }

  cleanupAutomationGlobals(window)
  cleanupDocumentAutomationMarkers(document)
  installDocumentAutomationObserver(document)

  if (window.Worker) {
    Object.defineProperty(window, 'Worker', {
      value: wrapWorkerConstructor(window.Worker, fingerprint, 'Worker'),
      configurable: true,
      writable: true,
      enumerable: false,
    })
  }

  if (window.SharedWorker) {
    Object.defineProperty(window, 'SharedWorker', {
      value: wrapSharedWorkerConstructor(window.SharedWorker, fingerprint),
      configurable: true,
      writable: true,
      enumerable: false,
    })
  }

  markModule('automation')
}