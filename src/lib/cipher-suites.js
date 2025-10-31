import { CURVES, Elliptic } from './elliptic.js'
import { sha256, sha512 } from './hash.js'
import { hmacSha256, hmacSha512 } from './hmac.js'
import { hkdfSha256, hkdfSha512 } from './kdf.js'
import { scrypt } from './mhf.js'

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
    hashFn: sha256,
    kdfFn: hkdfSha256,
    macFn: hmacSha256,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-ED25519-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P256-SHA256-HKDF-SHA256-HMAC-SHA256': createSuite({
    curve: CURVES.p256,
    hashFn: sha256,
    kdfFn: hkdfSha256,
    macFn: hmacSha256,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P256-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P256-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p256,
    hashFn: sha512,
    kdfFn: hkdfSha512,
    macFn: hmacSha512,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P256-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  }),
  'P384-SHA256-HKDF-SHA256-HMAC-SHA256': createSuite({
    curve: CURVES.p384,
    hashFn: sha256,
    kdfFn: hkdfSha256,
    macFn: hmacSha256,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P384-SHA256-HKDF-SHA256-HMAC-SHA256',
      spake2Plus: 'SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256'
    }
  }),
  'P384-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p384,
    hashFn: sha512,
    kdfFn: hkdfSha512,
    macFn: hmacSha512,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P384-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  }),
  'P521-SHA512-HKDF-SHA512-HMAC-SHA512': createSuite({
    curve: CURVES.p521,
    hashFn: sha512,
    kdfFn: hkdfSha512,
    macFn: hmacSha512,
    mhfFn: scrypt,
    suiteIds: {
      spake2: 'SPAKE2-P521-SHA512-HKDF-SHA512-HMAC-SHA512',
      spake2Plus: 'SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512'
    }
  })
}

export const cipherSuites = {
  ...suiteDefinitions,
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteDefinitions['ED25519-SHA256-HKDF-SHA256-HMAC-SHA256']
}
