# Browser Test Setup

These instructions let you run the browser compatibility check that bundles `@niomon/spake2` for the web and executes a SPAKE2+ round-trip in Chromium via Playwright.

## Prerequisites

```bash
npm install
npm install --save-dev playwright @rollup/plugin-node-polyfills @rollup/plugin-node-resolve @rollup/plugin-commonjs vite
npx playwright install chromium
```

## Running the test

The repository includes:

- `playwright.config.js` – Playwright configuration pointing at `tests/browser`.
- `tests/browser/setup.js` – Rollup bundling helper that produces `tests/browser/dist/bundle.js`.
- `tests/browser/spake2-demo.js` – Browser entry script that executes an SPAKE2+ flow and exposes the shared key.
- `tests/browser/spake2.spec.js` – Playwright test that bundles the code and asserts the shared key in Chromium.

Execute:

```bash
npm run test:browser
```

Add the following scripts to `package.json` if they are not present:

```json
{
  "scripts": {
    "test:browser": "node tests/browser/setup.js && npx playwright test --config=playwright.config.js"
  }
}
```

> The command above builds the browser bundle and then runs the Playwright test suite. Adjust the script to match your tooling if you already have a dedicated bundling step.

## Notes

- The tests assume `vite` is available. If you prefer another static server, modify `tests/browser/spake2.spec.js` to start/stop your server and update `baseURL` in `playwright.config.js`.
- Browser tests can be resource-intensive; run them in CI only if you install Playwright’s browsers during the setup stage.
