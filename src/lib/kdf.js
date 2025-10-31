import hashJs from 'hash.js'
import { toBytes, bufferFrom, concatBytes } from './bytes.js'

let nodeHkdf
try {
  const hkdfModule = await import('futoin-hkdf')
  nodeHkdf = hkdfModule.default || hkdfModule
} catch {
  nodeHkdf = undefined
}

function normalizeInput (value) {
  return toBytes(value)
}

function hkdfExtract (hashCtor, hashLen, ikm, salt) {
  const actualSalt = salt.length ? salt : new Uint8Array(hashLen)
  const prkArray = hashJs.hmac(hashCtor, actualSalt).update(ikm).digest()
  return Uint8Array.from(prkArray)
}

function hkdfExpand (hashCtor, hashLen, prk, info, length) {
  const blocks = Math.ceil(length / hashLen)
  if (blocks > 255) {
    throw new Error('hkdf: length is too large')
  }

  const okmParts = []
  let previous = new Uint8Array(0)
  for (let index = 0; index < blocks; index++) {
    const hmac = hashJs.hmac(hashCtor, prk)
    hmac.update(previous)
    hmac.update(info)
    hmac.update(Uint8Array.from([index + 1]))
    previous = Uint8Array.from(hmac.digest())
    okmParts.push(previous)
  }

  return concatBytes(...okmParts).subarray(0, length)
}

/**
 * A key derivation function (KDF) based on HMAC with SHA256.
 *
 * @param {Buffer} salt The salt for the HKDF.
 * @param {Buffer} ikm The input key material.
 * @param {Buffer|string} info The info for the KDF.
 * @param {number} [length=32] The desired output length in bytes.
 * @returns {Buffer} The derived key.
 */
export function hkdfSha256 (salt, ikm, info, length = 32) {
  const normalizedSalt = normalizeInput(salt)
  const normalizedInfo = normalizeInput(info)
  const normalizedIkm = normalizeInput(ikm)
  const hashCtor = hashJs.sha256
  const hashLen = hashCtor.outSize / 8

  if (nodeHkdf) {
    const result = nodeHkdf(bufferFrom(normalizedIkm), length, { salt: bufferFrom(normalizedSalt), info: bufferFrom(normalizedInfo), hash: 'SHA-256' })
    return new Uint8Array(result)
  }

  const prk = hkdfExtract(hashCtor, hashLen, normalizedIkm, normalizedSalt)
  return hkdfExpand(hashCtor, hashLen, prk, normalizedInfo, length)
}

/**
 * A key derivation function (KDF) based on HMAC with SHA512.
 *
 * @param {Buffer} salt The salt for the HKDF.
 * @param {Buffer} ikm The input key material.
 * @param {Buffer|string} info The info for the KDF.
 * @param {number} [length=64] The desired output length in bytes.
 * @returns {Buffer} The derived key.
 */
export function hkdfSha512 (salt, ikm, info, length = 64) {
  const normalizedSalt = normalizeInput(salt)
  const normalizedInfo = normalizeInput(info)
  const normalizedIkm = normalizeInput(ikm)
  const hashCtor = hashJs.sha512
  const hashLen = hashCtor.outSize / 8

  if (nodeHkdf) {
    const result = nodeHkdf(bufferFrom(normalizedIkm), length, { salt: bufferFrom(normalizedSalt), info: bufferFrom(normalizedInfo), hash: 'SHA-512' })
    return new Uint8Array(result)
  }

  const prk = hkdfExtract(hashCtor, hashLen, normalizedIkm, normalizedSalt)
  return hkdfExpand(hashCtor, hashLen, prk, normalizedInfo, length)
}
