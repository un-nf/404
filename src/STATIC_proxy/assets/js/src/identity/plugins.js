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

function defineNamedCollectionProperties(collection, namedKey) {
  for (const item of collection) {
    const key = item?.[namedKey]
    if (typeof key !== 'string' || !key || Object.prototype.hasOwnProperty.call(collection, key)) {
      continue
    }
    Object.defineProperty(collection, key, {
      value: item,
      configurable: true,
      writable: false,
      enumerable: false,
    })
  }
}

function freezeArrayCollection(items, namedKey) {
  const collection = items.slice()
  defineNamedCollectionProperties(collection, namedKey)
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

function buildMimeTypeEntry(item, enabledPlugin = null) {
  const entry = {
    type: item.type || item.name || 'application/pdf',
    suffixes: item.suffixes || 'pdf',
    description: item.description || 'Portable Document Format',
  }

  if (enabledPlugin) {
    Object.defineProperty(entry, 'enabledPlugin', {
      value: enabledPlugin,
      configurable: true,
      writable: false,
      enumerable: false,
    })
  }

  return Object.freeze(entry)
}

function buildPluginEntry(item) {
  const mimeTypeSpecs = Array.isArray(item.mimeTypes)
    ? item.mimeTypes.map((entry) => (typeof entry === 'string' ? { type: entry } : entry))
    : []
  const plugin = []

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

  for (const mimeType of mimeTypeSpecs) {
    plugin.push(buildMimeTypeEntry(mimeType, plugin))
  }

  defineNamedCollectionProperties(plugin, 'type')

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

function buildCollections(pluginItems, mimeTypeItems) {
  const pluginCollection = buildPluginArray(pluginItems)
  const combinedMimeTypes = []
  const seenMimeTypes = new Set()

  for (const plugin of pluginCollection) {
    for (const mimeType of plugin) {
      if (seenMimeTypes.has(mimeType.type)) {
        continue
      }
      seenMimeTypes.add(mimeType.type)
      combinedMimeTypes.push(mimeType)
    }
  }

  for (const item of mimeTypeItems) {
    const entry = buildMimeTypeEntry(item)
    if (seenMimeTypes.has(entry.type)) {
      continue
    }
    seenMimeTypes.add(entry.type)
    combinedMimeTypes.push(entry)
  }

  return {
    plugins: pluginCollection,
    mimeTypes: freezeArrayCollection(combinedMimeTypes, 'type'),
  }
}

function normalizePluginEntries(pluginEntries, mimeTypeEntries) {
  if (mimeTypeEntries.length === 0) {
    return pluginEntries
  }

  return pluginEntries.map((entry) => {
    if (Array.isArray(entry.mimeTypes) && entry.mimeTypes.length > 0) {
      return entry
    }

    return {
      ...entry,
      mimeTypes: mimeTypeEntries.map((mimeType) => ({ ...mimeType })),
    }
  })
}

function defineNavigatorCollectionGetter(name, value) {
  const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, name)
  Object.defineProperty(Navigator.prototype, name, {
    get: markNativeCode(function getter() {
      return value
    }, name),
    configurable: descriptor?.configurable ?? true,
    enumerable: descriptor?.enumerable ?? true,
  })
}

export function installPlugins() {
  const fingerprint = getFingerprint()
  const defaults = [{ name: 'PDF Viewer', mimeTypes: ['application/pdf'] }]

  const pluginEntries = Array.isArray(fingerprint.plugins)
    ? fingerprint.plugins.map((entry) => (typeof entry === 'string' ? { name: entry } : entry))
    : typeof fingerprint.plugins === 'string'
      ? [{ name: fingerprint.plugins }]
      : defaults

  const mimeTypeEntries = Array.isArray(fingerprint.mimeTypes)
    ? fingerprint.mimeTypes.map((type) => (typeof type === 'string' ? { type } : type))
    : []

  const collections = buildCollections(
    normalizePluginEntries(pluginEntries, mimeTypeEntries),
    mimeTypeEntries,
  )

  defineNavigatorCollectionGetter('plugins', collections.plugins)
  defineNavigatorCollectionGetter('mimeTypes', collections.mimeTypes)

  markModule('plugins')
}