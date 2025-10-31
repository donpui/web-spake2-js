import { test, expect } from '@playwright/test'
import path from 'path'
import { fileURLToPath } from 'url'

import { buildBundle } from './setup.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const projectRoot = path.resolve(__dirname, '..', '..')

test.beforeAll(async () => {
  await buildBundle()
})

test('SPAKE2+ runs in browser', async ({ page }) => {
  await page.setContent('<html><body></body></html>')
  const bundlePath = path.resolve(projectRoot, 'tests', 'browser', 'dist', 'bundle.js')
  await page.addScriptTag({ path: bundlePath, type: 'module' })
  await page.evaluate(() => window.runSpake2Demo())
  const sharedHex = await page.evaluate(() => window.__spake2SharedKeyHex)
  expect(sharedHex).toHaveLength(64)
})
