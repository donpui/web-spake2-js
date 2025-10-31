const hashJs = require('hash.js')
const { toBytes, bufferFrom } = require('./bytes.js')

let nodeCreateHash
try {
  ({ createHash: nodeCreateHash } = require('crypto'))
} catch (error) {
  nodeCreateHash = undefined
}

/**
 * Computes a hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @returns {Buffer} The hashed content.
 */
function sha256 (content) {
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
function sha512 (content) {
  const input = toBytes(content)
  if (nodeCreateHash) {
    const digest = nodeCreateHash('sha512').update(bufferFrom(input)).digest()
    return new Uint8Array(digest)
  }
  return Uint8Array.from(hashJs.sha512().update(input).digest())
}

exports.sha256 = sha256
exports.sha512 = sha512
