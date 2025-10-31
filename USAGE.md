# SPAKE2-JS Usage Guide

This guide walks through the practical steps for using `web-spake2-js` to run SPAKE2 and SPAKE2+ exchanges in Node.js applications. It complements the brief README with concrete instructions, code snippets, and option details.

> ⚠️ **Security note**  
> This library has not been audited by cryptographers, and many operations are not constant time. Deploy only after a thorough review tailored to your threat model.

---

## 1. Installation and Runtime

```bash
npm install web-spake2-js
# or
yarn add web-spake2-js
```

The test suite is exercised on Node.js 18+; Node.js 22 works as well. Ensure you run on a modern Node.js release with the built-in `crypto` module available.

### Importing

```js
// CommonJS
const { spake2, spake2Plus } = require('web-spake2-js')

// ESM / bundlers
import { spake2, spake2Plus } from 'web-spake2-js'
```

All byte-oriented APIs return `Uint8Array` values. In Node.js you can call the provided `.toBuffer()` helpers (or wrap with `Buffer.from(...)`) for compatibility, while browsers can consume the `Uint8Array` instances directly.

---

## 2. Selecting a Cipher Suite

Cipher suites encode the elliptic curve, hash, HKDF, and MAC algorithms. The library exposes the following identifiers (all pulled from RFCs 9382 & 9383):

| Identifier | Curve | Hash/HKDF | MAC |
|------------|-------|-----------|-----|
| `ED25519-SHA256-HKDF-SHA256-HMAC-SHA256` | Ed25519 | SHA-256 | HMAC-SHA256 |
| `P256-SHA256-HKDF-SHA256-HMAC-SHA256` | P-256 | SHA-256 | HMAC-SHA256 |
| `P256-SHA512-HKDF-SHA512-HMAC-SHA512` | P-256 | SHA-512 | HMAC-SHA512 |
| `P384-SHA256-HKDF-SHA256-HMAC-SHA256` | P-384 | SHA-256 | HMAC-SHA256 |
| `P384-SHA512-HKDF-SHA512-HMAC-SHA512` | P-384 | SHA-512 | HMAC-SHA512 |
| `P521-SHA512-HKDF-SHA512-HMAC-SHA512` | P-521 | SHA-512 | HMAC-SHA512 |

> Legacy name: `ED25519-SHA256-HKDF-HMAC-SCRYPT` still maps to the Ed25519 suite for backward compatibility.

Pick a suite that matches the curve and hash requirements of your environment. Ed25519 is the default if you omit the `suite` option.

---

## 3. MHF (Password Hashing) Parameters

SPAKE2(+) relies on an MHF (memory-hard function) to turn user passwords into scalars. The library ships with `scrypt` as the MHF. Configure it via the `mhf` option when creating a SPAKE2 instance:

```js
const mhfOptions = {
  n: 32768, // CPU/memory cost (power of two, >= 2^4)
  r: 8,     // block size
  p: 1,     // parallelization
  length: undefined // optional derived key length override (bytes)
}
```

If you omit `length`, the library derives the required lengths automatically based on the selected curve (including extra entropy to keep bias below 2⁻⁶⁴).

---

## 4. Running SPAKE2 (Balanced PAKE)

The balanced protocol assumes both sides share the password. Typical flow:

```js
const spake2 = require('web-spake2-js')

const options = {
  suite: 'P256-SHA256-HKDF-SHA256-HMAC-SHA256',
  mhf: { n: 32768, r: 8, p: 1 },
  kdf: { AAD: 'my-protocol-v1' } // optional associated data for confirmation keys
}

const serverIdentity = 'server'
const clientIdentity = 'client'
const password = 'correct horse battery staple'
const salt = 'unique-per-user-salt'

// Both sides agree on the verifier beforehand if you use an authenticated verifier store.
const s = spake2.spake2(options)
const verifier = await s.computeVerifier(password, salt) // Uint8Array
```

### Client side
```js
const clientState = await s.startClient(clientIdentity, serverIdentity, password, salt)
const clientMessage = clientState.getMessage() // send to server
```

### Server side
```js
const serverState = await s.startServer(clientIdentity, serverIdentity, verifier)
const serverMessage = serverState.getMessage() // send to client

const serverSecret = serverState.finish(clientMessage)
const confirmationFromServer = serverSecret.getConfirmation() // send to client
```

### Back on the client
```js
const clientSecret = clientState.finish(serverMessage)
const confirmationFromClient = clientSecret.getConfirmation() // send to server

// Verify confirmations (throws on mismatch).
serverSecret.verify(confirmationFromClient)
clientSecret.verify(confirmationFromServer)

// Both sides now have the same shared key material.
const sharedSecretClient = clientSecret.toUint8Array()
const sharedSecretServer = serverSecret.toUint8Array()
```

### Persisting state (optional)

`ClientSPAKE2State`, `ServerSPAKE2State`, `ClientSharedSecret`, and `ServerSharedSecret` each support `.save()` and static `.load(savedState)` helpers. This is useful if you must pause an exchange and resume later.

---

## 5. Running SPAKE2+ (Augmented PAKE)

SPAKE2+ is asymmetrical: the client knows the password, the server stores a verifier (`w0`, `L`). Registration happens offline:

```js
const sPlus = spake2.spake2Plus({
  suite: 'P256-SHA512-HKDF-SHA512-HMAC-SHA512',
  mhf: { n: 32768, r: 8, p: 1 },
  kdf: { AAD: 'my-protocol-v1' },
  context: 'Custom domain separation string' // optional; defaults to RFC suite string
})

const verifierRecord = await sPlus.computeVerifier(password, salt, clientIdentity, serverIdentity)
// => { w0: Buffer, L: Buffer } – store this securely on the server.
```

**Online exchange**

Client (`password` required):
```js
const client = await sPlus.startClient(clientIdentity, serverIdentity, password, salt)
const X = client.getMessage()
// send X to server
```

Server (password not required, only the stored verifier):
```js
const server = await sPlus.startServer(clientIdentity, serverIdentity, verifierRecord)
const Y = server.getMessage()
const serverSecret = server.finish(X)
const confirmServer = serverSecret.getConfirmation()
// send Y and confirmServer to client
```

Client completes:
```js
const clientSecret = client.finish(Y)
clientSecret.verify(confirmServer) // throws if MAC mismatch
const confirmClient = clientSecret.getConfirmation()
// send confirmClient back to server
```

Server finishes:
```js
serverSecret.verify(confirmClient) // throws if mismatch
const sharedKey = serverSecret.toUint8Array()
```

For SPAKE2+, `toBuffer()` returns the HKDF-derived shared key from RFC 9383 (“SharedKey”). The confirmation MACs are computed over the peer’s share (`X` for the server, `Y` for the client) as mandated by the spec.

---

## 6. Options Reference

| Option | Location | Purpose |
|--------|----------|---------|
| `suite` | constructor options | Selects cipher suite. Default is Ed25519/SHA-256. |
| `plus` | internal flag | Set via `.spake2()` (false) or `.spake2Plus()` (true). |
| `mhf.n`, `mhf.r`, `mhf.p`, `mhf.length` | constructor options | Controls the scrypt MHF parameters. |
| `kdf.AAD` | constructor options | Optional associated data concatenated to `"ConfirmationKeys"` and `"SharedKey"` info strings. |
| `context` | SPAKE2+ only | Domain-separation context for transcripts. Defaults to the RFC suite identifier. |

When loading saved state objects, you may omit `suite`; the loader defaults to `ED25519-SHA256-HKDF-SHA256-HMAC-SHA256`.

---

## 7. Testing and Verification

1. Run the bundled test suite:
   ```bash
   npm test
   ```
   Each test exercises SPAKE2 and SPAKE2+ against official RFC vectors.

2. Integrate application-layer tests that cover persistence (`save()`/`load()`) and confirmation failure handling.

3. Review the RFCs (9382 for SPAKE2, 9383 for SPAKE2+) to ensure your usage respects protocol constraints, especially regarding password normalization, salt management, and identity handling.

---

## 8. Best Practices and Caveats

- **Randomness**: Do not reuse `clientState.getMessage()` outputs. Each exchange must generate fresh random scalars.
- **Identity handling**: Always provide explicit identities to avoid unknown-key-share vulnerabilities.
- **Error handling**: Treat any thrown error during `finish()` or `verify()` as a fatal authentication failure.
- **Side-channel resistance**: Upstream code is not constant-time. Keep keys isolated and consider additional hardening if you deploy in environments where timing leakage matters.
- **Upgrades**: Changes in scrypt parameters or cipher suites require all parties to agree beforehand.

---

## 9. Further Reading

- [RFC 9382 – SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
- [RFC 9383 – SPAKE2+](https://www.rfc-editor.org/rfc/rfc9383)
- [RFC 7914 – scrypt](https://www.rfc-editor.org/rfc/rfc7914)

Consult these documents for formal protocol descriptions and parameter recommendations.
