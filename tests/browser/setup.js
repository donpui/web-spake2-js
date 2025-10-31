const path = require('path')
const { mkdirSync } = require('fs')

async function buildBundle () {
  const { rollup } = await import('rollup')
  const { default: nodePolyfills } = await import('rollup-plugin-node-polyfills')
  const { default: resolve } = await import('@rollup/plugin-node-resolve')
  const { default: commonjs } = await import('@rollup/plugin-commonjs')
  const { default: json } = await import('@rollup/plugin-json')
  const { default: inject } = await import('@rollup/plugin-inject')
  const { default: alias } = await import('@rollup/plugin-alias')

  const projectRoot = path.resolve(__dirname, '..', '..')
  const entry = path.join(__dirname, 'spake2-demo.js')
  const outputDir = path.join(projectRoot, 'tests', 'browser', 'dist')
  const bundleFile = path.join(outputDir, 'bundle.js')

  mkdirSync(outputDir, { recursive: true })

  const bundle = await rollup({
    input: entry,
    plugins: [
      alias({
        entries: [
          { find: 'crypto', replacement: 'crypto-browserify' },
          { find: 'stream', replacement: 'stream-browserify' }
        ]
      }),
      json(),
      resolve({ browser: true, preferBuiltins: false }),
      commonjs(),
      inject({
        Buffer: ['buffer', 'Buffer'],
        process: 'process'
      }),
      nodePolyfills()
    ]
  })

  await bundle.write({
    file: bundleFile,
    format: 'iife',
    name: 'Spake2Bundle'
  })
}

module.exports = { buildBundle }
