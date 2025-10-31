const { CURVES, Elliptic } = require('./elliptic.js')
const hash = require('./hash.js')
const hmac = require('./hmac.js')
const kdf = require('./kdf.js')
const mhf = require('./mhf.js')

/**
 * @typedef {object} CipherSuite
 * @property {Elliptic} curve An elliptic curve.
 * @property {Function} hash A hash function.
 * @property {Function} kdf A key derivation function.
 * @property {Function} mac A message authentication code function.
 * @property {Function} mhf A memory-hard hash function.
 * @property {object} suiteIds Identifiers for SPAKE2 and SPAKE2+ contexts.
 * @property {string} [suiteIds.spake2] Identifier string for SPAKE2.
 * @property {string} [suiteIds.spake2Plus] Identifier string for SPAKE2+.
 */

function createSuite ({ curve, hashFn, kdfFn, macFn, mhfFn, suiteIds }) {
  const elliptic = new Elliptic(curve)
  const hashLength = hashFn(new Uint8Array(0)).length
  return {
    curve: elliptic,
    hash: hashFn,
    kdf: kdfFn,
    mac: macFn,
    mhf: mhfFn,
    suiteIds,
    scalarLength: elliptic.scalarLength,
    scalarBitLength: elliptic.scalarBitLength,
    hashLength
  }
}

const suiteDefinitions = {
  'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256': createSuite({
    curve: CURVES.ed25519,
    hashFn: hash.sha256,
    kdfFn: kdf.hkdfSha256,
    macFn: hmac.hmacSha256,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-ED25519-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P256-SHA256-HKDF-SHA256-HMAC-SHA256': createSuite({
    curve: CURVES.p256,
    hashFn: hash.sha256,
    kdfFn: kdf.hkdfSha256,
    macFn: hmac.hmacSha256,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P256-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P256-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p256,
    hashFn: hash.sha512,
    kdfFn: kdf.hkdfSha512,
    macFn: hmac.hmacSha512,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P256-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  }),
  'P384-SHA256-HKDF-SHA256-HMAC-SHA256': createSuite({
    curve: CURVES.p384,
    hashFn: hash.sha256,
    kdfFn: kdf.hkdfSha256,
    macFn: hmac.hmacSha256,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P384-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P384-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p384,
    hashFn: hash.sha512,
    kdfFn: kdf.hkdfSha512,
    macFn: hmac.hmacSha512,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P384-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  }),
  'P521-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p521,
    hashFn: hash.sha512,
    kdfFn: kdf.hkdfSha512,
    macFn: hmac.hmacSha512,
    mhfFn: mhf.scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P521-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  })
}

const cipherSuites = {
  ...suiteDefinitions,
  // Backwards compatibility with previous suite naming.
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteDefinitions['ED25519-SHA256-HKDF-SHA256-HMAC-SHA256']
}

exports.cipherSuites = cipherSuites
