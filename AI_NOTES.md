# Notes for future investigation

• Key Findings (ordered by severity)

  - Transcript encoding diverges from the spec. concatLengthPrefixed drops any element whose length is zero (src/lib/bytes.js:39). RFC 9382/9383 requires emitting the 8‑byte little‑endian length for every field, even when the payload
    is empty. Because the zero-length fields are skipped, different inputs (for example, an explicit empty identity vs. an absent identity) can produce identical transcripts. That removes the domain-separation guarantee the transcript
    provides and risks protocol misuse or unknown-key-share issues. Fix: always serialize the length (including the eight zero bytes) before the data, never skip entries.
  - Browser bundle still depends on Node polyfills for crypto primitives. The Playwright setup (tests/browser/setup.js:12-31) injects crypto-browserify, stream-browserify, polyfills for Buffer, process, etc. The exported library
    itself doesn’t provide a WebCrypto-backed implementation; it only works in a browser when a bundler rewrites those imports to Node shims. Consumers who import the ESM build directly in the browser will fail at runtime. If “browser
    compatibility” is a goal, consider offering a pure-WebCrypto build (or at least documenting the bundler requirement) so the security model is explicit.
  - HKDF/SHA/HMAC fallbacks use hash.js, which isn’t constant time. When the native Node crypto module isn’t available (src/lib/hash.js:16, src/lib/hmac.js:21, src/lib/kdf.js:16-24), the implementation falls back to the pure-JS hash.js
    package. That code path runs entirely in JavaScript; it’s not constant time and was never designed for production KDF/HMAC usage. If you’re targeting browsers, prefer the native WebCrypto API (SHA-256/SHA-512, HMAC, HKDF) instead of
    relying on a software-only fallback.
  - Scrypt default parameters remain unconstrained. The API exposes n, r, p, but it sets no minimums and doesn’t sanity-check the values (src/lib/mhf.js:21-62). A malicious caller can set n=1 to shrink the cost. Spec guidance is to
    enforce sensible lower bounds (e.g., n >= 2^14, r >= 8, p >= 1). If this library is used as part of a password authentication flow, the application must enforce safe MHF parameters explicitly.
  - Testing currently relies on experimental Node flags. Unit-test scripts invoke Jest with --experimental-vm-modules (package.json:13-14) because running tests as native ESM without this flag failed in this environment. Longer-term
    options: migrate test files to .mjs, introduce a minimal Babel transform for tests, or switch to a runner with first-class ESM support to remove the experimental flag.

  Recommendations

  1. Fix concatLengthPrefixed so zero-length values still emit their length field.
  2. Decide whether to ship a true browser build (WebCrypto-based) or keep the “Node + bundler” stance; document clearly that bundler polyfills are required.
  3. Replace the hash.js fallback with WebCrypto implementations (via crypto.subtle) when Node’s crypto isn’t available; that provides a constant-time, vetted path in both environments.
  4. Add input validation for MHF parameters (and document recommended defaults).
  5. Long-term, move to a Jest setup (or alternative test runner) that doesn’t need experimental Node flags once the project is fully ESM.