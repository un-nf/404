import { getFingerprint } from '../core/config.js'
import { markModule } from '../core/guard.js'
import { markNativeCode } from '../core/toString.js'

function defineCollectionMethod(target, name, fn) {
  Object.defineProperty(target, name, {
    value: markNativeCode(fn, name),
    configurable: true,
    writable: true,
    enumerable: false,
  })
}

function freezeArrayCollection(items, namedKey) {
  const collection = items.slice()
  defineCollectionMethod(collection, 'item', function item(index) {
    return collection[index] ?? null
  })
  defineCollectionMethod(collection, 'namedItem', function namedItem(name) {
    return collection.find((item) => item?.[namedKey] === name) ?? null
  })
  defineCollectionMethod(collection, 'refresh', function refresh() {
    return undefined
  })
  return Object.freeze(collection)
}

function buildMimeTypeEntry(item) {
  return Object.freeze({
    type: item.type || item.name || 'application/pdf',
    suffixes: item.suffixes || 'pdf',
    description: item.description || 'Portable Document Format',
  })
}

function buildPluginEntry(item) {
  const mimeTypes = Array.isArray(item.mimeTypes)
    ? item.mimeTypes.map((entry) => buildMimeTypeEntry(typeof entry === 'string' ? { type: entry } : entry))
    : []
  const plugin = mimeTypes.slice()

  Object.defineProperty(plugin, 'name', {
    value: item.name,
    configurable: true,
    writable: false,
    enumerable: false,
  })
  Object.defineProperty(plugin, 'description', {
    value: item.description || 'Portable Document Format',
    configurable: true,
    writable: false,
    enumerable: false,
  })
  Object.defineProperty(plugin, 'filename', {
    value: item.filename || 'internal-pdf-viewer',
    configurable: true,
    writable: false,
    enumerable: false,
  })

  defineCollectionMethod(plugin, 'item', function item(index) {
    return plugin[index] ?? null
  })
  defineCollectionMethod(plugin, 'namedItem', function namedItem(name) {
    return plugin.find((entry) => entry?.type === name) ?? null
  })

  return Object.freeze(plugin)
}

function buildPluginArray(items) {
  return freezeArrayCollection(items.map(buildPluginEntry), 'name')
}

function buildMimeTypeArray(items) {
  return freezeArrayCollection(items.map(buildMimeTypeEntry), 'type')
}

export function installPlugins() {
  const fingerprint = getFingerprint()
  const browserType = fingerprint.browser_type || 'chrome'
  const defaults = browserType === 'firefox'
    ? []
    : [
        { name: 'PDF Viewer', mimeTypes: ['application/pdf'] },
        { name: 'Chrome PDF Viewer', mimeTypes: ['application/pdf'] },
        { name: 'Chromium PDF Viewer', mimeTypes: ['application/pdf'] },
      ]

  const plugins = Array.isArray(fingerprint.plugins)
    ? fingerprint.plugins.map((entry) => (typeof entry === 'string' ? { name: entry } : entry))
    : typeof fingerprint.plugins === 'string'
      ? [{ name: fingerprint.plugins }]
      : defaults

  const mimeTypes = Array.isArray(fingerprint.mimeTypes)
    ? fingerprint.mimeTypes.map((type) => (typeof type === 'string' ? { type } : type))
    : []

  Object.defineProperty(Navigator.prototype, 'plugins', {
    get: markNativeCode(function plugins() {
      return buildPluginArray(plugins)
    }, 'plugins'),
    configurable: true,
    enumerable: true,
  })

  Object.defineProperty(Navigator.prototype, 'mimeTypes', {
    get: markNativeCode(function mimeTypesGetter() {
      return buildMimeTypeArray(mimeTypes)
    }, 'mimeTypes'),
    configurable: true,
    enumerable: true,
  })

  markModule('plugins')
}