import hashJs from 'hash.js'
import { toBytes, bufferFrom } from './bytes.js'

let nodeCreateHmac
try {
  const cryptoModule = await import('crypto')
  nodeCreateHmac = cryptoModule.createHmac
} catch {
  nodeCreateHmac = undefined
}

/**
 * Computes a key-hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @param {Buffer} secret The secret key to compute the hash.
 * @returns {Buffer} The key-hashed content.
 */
export function hmacSha256 (content, secret) {
  const data = toBytes(content)
  const key = toBytes(secret)
  if (nodeCreateHmac) {
    return new Uint8Array(nodeCreateHmac('sha256', bufferFrom(key)).update(bufferFrom(data)).digest())
  }
  return Uint8Array.from(hashJs.hmac(hashJs.sha256, key).update(data).digest())
}

/**
 * Computes a key-hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA512) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @param {Buffer} secret The secret key to compute the hash.
 * @returns {Buffer} The key-hashed content.
 */
export function hmacSha512 (content, secret) {
  const data = toBytes(content)
  const key = toBytes(secret)
  if (nodeCreateHmac) {
    return new Uint8Array(nodeCreateHmac('sha512', bufferFrom(key)).update(bufferFrom(data)).digest())
  }
  return Uint8Array.from(hashJs.hmac(hashJs.sha512, key).update(data).digest())
}
