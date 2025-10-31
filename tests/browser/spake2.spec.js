const { test, expect } = require('@playwright/test')
const path = require('path')
const { buildBundle } = require('./setup')
const projectRoot = path.resolve(__dirname, '..', '..')

test.beforeAll(async () => {
  await buildBundle()
})

test('SPAKE2+ runs in browser', async ({ page }) => {
  await page.setContent('<html><body></body></html>')
  const bundlePath = path.resolve(projectRoot, 'tests', 'browser', 'dist', 'bundle.js')
  await page.addScriptTag({ path: bundlePath })
  await page.evaluate(() => window.runSpake2Demo())
  const sharedHex = await page.evaluate(() => window.__spake2SharedKeyHex)
  expect(sharedHex).toHaveLength(64)
})
