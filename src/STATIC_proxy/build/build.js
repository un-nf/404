const esbuild = require('esbuild')
const fs = require('fs')
const path = require('path')

const root = __dirname
const entryPoint = path.join(root, '..', 'assets', 'js', 'src', 'runtime.js')
const outfile = process.env.STATIC_BUNDLE_OUTFILE || path.join(root, '..', 'assets', 'js', 'dist', 'runtime.bundle.js')
const outdir = path.dirname(outfile)
const watch = process.argv.includes('--watch')

fs.mkdirSync(outdir, { recursive: true })

const config = {
  entryPoints: [entryPoint],
  bundle: true,
  format: 'iife',
  outfile,
  minify: false,
  sourcemap: false,
  target: ['chrome120', 'firefox120', 'safari17'],
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  logLevel: 'info',
}

async function main() {
  if (watch) {
    const ctx = await esbuild.context(config)
    await ctx.watch()
    return
  }

  await esbuild.build(config)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})