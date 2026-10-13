const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { chromium } = require(process.env.STATIC_PLAYWRIGHT_MODULE || 'playwright')
const root = path.resolve(__dirname, '..')
const bundle = fs.readFileSync(path.join(root, 'assets/js/dist/runtime.bundle.js'), 'utf8')
const raw = JSON.parse(fs.readFileSync(path.join(root, 'profiles/chrome-windows.json'), 'utf8'))
raw.startup_salt = 'private-browser-test-salt'
raw.fingerprint.name = 'Hawaiʻi 中文'
const encoded = Buffer.from(JSON.stringify(raw)).toString('base64')
const keys = ['__STATIC_RUNTIME__', '__STATIC_CONFIG__', '__STATIC_FINGERPRINT__', '__fpConfig',
  '__static_rng', '__static_hash', '__STATIC_CSP_NONCE', '__404_canvas_fingerprint',
  'staticRuntimeModule', 'createStaticRealmRuntime']

async function main() {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.STATIC_BROWSER_EXECUTABLE ? { executablePath: process.env.STATIC_BROWSER_EXECUTABLE } : {}) })
  try {
    console.log(`Browser version: ${browser.version()}`)
    const page = await browser.newPage()
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (msg) => { if (msg.type() === 'error') errors.push(msg.text()) })
    await page.route('https://fixture.test/**', async (route) => {
      const url = new URL(route.request().url())
      if (url.pathname === '/__static/runtime.js') {
        await route.fulfill({ contentType: 'text/javascript', body: bundle }); return
      }
      const preseed = url.pathname === '/preseed' ?
        '<script>window.__STATIC_RUNTIME__={version:"5.0.0",nativeRefs:{attacker:true}};window.__STATIC_CSP_NONCE="attacker";</script>' : ''
      const config = url.pathname === '/invalid' ? Buffer.from('{}').toString('base64') : encoded
      await route.fulfill({ contentType: 'text/html',
        ...(url.pathname === '/csp' ? { headers: { 'content-security-policy': "script-src 'self'" } } : {}),
        body: `<!doctype html><html><head>${preseed}
        <script src="/__static/runtime.js" data-static-config-b64="${config}"></script>
        </head><body></body></html>` })
    })
    await page.goto('https://fixture.test/')
    assert.deepEqual(await page.evaluate((names) => names.filter((name) => Object.getOwnPropertyNames(window).includes(name)), keys), [])
    assert.equal(await page.evaluate(() => navigator.userAgent), raw.fingerprint.user_agent)
    assert.equal(await page.evaluate(() => document.querySelector('[data-static-config-b64]')), null)
    assert.equal(await page.evaluate(async () => {
      const brands = navigator.userAgentData.brands
      try { brands[0].brand = 'attacker' } catch {}
      return (await navigator.userAgentData.getHighEntropyValues([])).brands[0].brand
    }), raw.fingerprint.ua_data.brands[0].brand)
    assert.equal(await page.evaluate(() => {
      const canvas = document.createElement('canvas'); canvas.width = canvas.height = 32
      const ctx = canvas.getContext('2d'); ctx.fillStyle = '#334455'; ctx.fillRect(0, 0, 32, 32)
      const a = ctx.getImageData(0, 0, 32, 32); const b = ctx.getImageData(0, 0, 32, 32)
      return a.data.length === 4096 && a.data.every((value, i) => value === b.data[i])
    }), true)
    console.log('PASS: production globals, DOM carrier, frozen persona, canvas repeatability')

    const frameResult = await page.evaluate(async ({ ua, names }) => {
      const wrapper = document.createElement('div'); wrapper.innerHTML = '<iframe></iframe>'
      document.body.append(wrapper)
      const frame = wrapper.firstChild
      await new Promise((resolve) => setTimeout(resolve, 50))
      const child = frame.contentWindow
      const result = {
        ua: child.navigator.userAgent,
        ownFunction: child.CanvasRenderingContext2D.prototype.getImageData !== CanvasRenderingContext2D.prototype.getImageData,
        globals: names.filter((name) => Object.getOwnPropertyNames(child).includes(name)),
      }
      frame.srcdoc = '<html><body>new realm</body></html>'
      await new Promise((resolve) => frame.addEventListener('load', resolve, { once: true }))
      await new Promise((resolve) => setTimeout(resolve, 50))
      result.afterNavigation = frame.contentWindow.navigator.userAgent === ua
      return result
    }, { ua: raw.fingerprint.user_agent, names: keys })
    assert.equal(frameResult.ua, raw.fingerprint.user_agent)
    assert.equal(frameResult.ownFunction, true)
    assert.deepEqual(frameResult.globals, [])
    assert.equal(frameResult.afterNavigation, true)
    console.log('PASS: nested about:blank frame, independent wrapper ownership, srcdoc navigation')

    await page.goto('https://fixture.test/preseed')
    assert.equal(await page.evaluate(() => navigator.userAgent), raw.fingerprint.user_agent)
    assert.deepEqual(await page.evaluate(() => window.__STATIC_RUNTIME__), { version: '5.0.0', nativeRefs: { attacker: true } })
    console.log('PASS: forged same-version registry cannot suppress installation')
    assert.deepEqual(errors, [])

    await page.goto('https://fixture.test/invalid')
    assert.notEqual(await page.evaluate(() => navigator.userAgent), raw.fingerprint.user_agent)
    assert.deepEqual(await page.evaluate((names) => names.filter((name) => Object.hasOwn(window, name)), keys), [])
    assert.equal(errors.length, 1)
    assert.match(errors[0], /profile missing required fields/)
    console.log('PASS: invalid profile rejects before patches')

    await page.goto('https://fixture.test/csp')
    assert.equal(await page.evaluate(() => navigator.userAgent), raw.fingerprint.user_agent)
    const blockedFrame = await page.evaluate(async () => {
      const frame = document.createElement('iframe'); document.body.append(frame)
      await new Promise((resolve) => setTimeout(resolve, 50))
      return { ua: frame.contentWindow.navigator.userAgent,
        globals: Object.getOwnPropertyNames(frame.contentWindow).filter((name) => name.startsWith('__STATIC_')) }
    })
    assert.notEqual(blockedFrame.ua, raw.fingerprint.user_agent)
    assert.deepEqual(blockedFrame.globals, [])
    console.log('PASS: strict CSP leaves fallback frame uncovered without sharing parent services')
  } finally {
    await browser.close()
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1 })
