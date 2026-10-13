import { definePatch, deletePatch, onRollback } from '../core/patches.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'
import { replaceGetter, mapMethod } from '../core/descriptors.js'
import { getFingerprint } from '../core/config.js'

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
    deletePatch(target, name)
  } catch {
    // ignore
  }

  if (!(name in target)) {
    return
  }

  try {
    definePatch(target, name, {
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
    deletePatch(target, name)
  } catch {
    // ignore
  }

  if (!(name in target)) {
    return
  }

  try {
    definePatch(target, name, {
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
      const value = root.getAttribute(key)
      if (value !== null) onRollback(() => root.setAttribute(key, value))
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
  onRollback(() => observer.disconnect())
}

export function installAutomationEvasion() {
  const fp=getFingerprint()
  if(fp.visibility_state!==undefined) {
    replaceGetter(Document.prototype,'visibilityState',()=>fp.visibility_state)
    replaceGetter(Document.prototype,'hidden',()=>fp.visibility_state==='hidden')
  }
  if(fp.has_focus!==undefined)mapMethod(Document.prototype,'hasFocus',()=>fp.has_focus)

  replaceGetter(Navigator.prototype, 'webdriver', () => false)

  cleanupAutomationGlobals(window)
  cleanupDocumentAutomationMarkers(document)
  installDocumentAutomationObserver(document)

  markModule('automation',{status:fp.visibility_state!==undefined||fp.has_focus!==undefined?'partial':'installed',
    detail:'profile-declared focus/visibility queries; actual events, throttling and focus operations are not virtualized'})
}
