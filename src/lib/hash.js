import hashJs from 'hash.js'
import { toBytes, bufferFrom } from './bytes.js'

let nodeCreateHash
try {
  const cryptoModule = await import('crypto')
  nodeCreateHash = cryptoModule.createHash
} catch {
  nodeCreateHash = undefined
}

/**
 * Computes a hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @returns {Buffer} The hashed content.
 */
export function sha256 (content) {
  const input = toBytes(content)
  if (nodeCreateHash) {
    const digest = nodeCreateHash('sha256').update(bufferFrom(input)).digest()
    return new Uint8Array(digest)
  }
  return Uint8Array.from(hashJs.sha256().update(input).digest())
}

/**
 * Computes a hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA512) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @returns {Buffer} The hashed content.
 */
export function sha512 (content) {
  const input = toBytes(content)
  if (nodeCreateHash) {
    const digest = nodeCreateHash('sha512').update(bufferFrom(input)).digest()
    return new Uint8Array(digest)
  }
  return Uint8Array.from(hashJs.sha512().update(input).digest())
}
