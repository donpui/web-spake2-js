import path from 'path'
import { mkdirSync } from 'fs'
import { fileURLToPath } from 'url'

const { rollup } = await import('rollup')
const { default: nodePolyfills } = await import('rollup-plugin-node-polyfills')
const { default: resolve } = await import('@rollup/plugin-node-resolve')
const { default: commonjs } = await import('@rollup/plugin-commonjs')
const { default: json } = await import('@rollup/plugin-json')
const { default: inject } = await import('@rollup/plugin-inject')
const { default: alias } = await import('@rollup/plugin-alias')

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const projectRoot = path.resolve(__dirname, '..', '..')
const entry = path.join(__dirname, 'spake2-demo.js')
const outputDir = path.join(projectRoot, 'tests', 'browser', 'dist')
const bundleFile = path.join(outputDir, 'bundle.js')

export async function buildBundle () {
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
    format: 'es',
    inlineDynamicImports: true
  })
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  await buildBundle()
}
