const hashJs = require('hash.js')
const { toBytes, bufferFrom } = require('./bytes.js')

let nodeCreateHmac
try {
  ({ createHmac: nodeCreateHmac } = require('crypto'))
} catch (error) {
  nodeCreateHmac = undefined
}

/**
 * Computes a key-hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @param {Buffer} secret The secret key to compute the hash.
 * @returns {Buffer} The key-hashed content.
 */
function hmacSha256 (content, secret) {
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
function hmacSha512 (content, secret) {
  const data = toBytes(content)
  const key = toBytes(secret)
  if (nodeCreateHmac) {
    return new Uint8Array(nodeCreateHmac('sha512', bufferFrom(key)).update(bufferFrom(data)).digest())
  }
  return Uint8Array.from(hashJs.hmac(hashJs.sha512, key).update(data).digest())
}

exports.hmacSha256 = hmacSha256
exports.hmacSha512 = hmacSha512
