import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/browser',
  use: {
    browserName: 'chromium',
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
  },
});
