import BN from 'bn.js'
import { toHex } from './bytes.js'

let nodeCrypto
try {
  nodeCrypto = await import('crypto')
} catch {
  nodeCrypto = undefined
}

function randomBytes (size) {
  if (nodeCrypto && typeof nodeCrypto.randomBytes === 'function') {
    const buf = nodeCrypto.randomBytes(size)
    return new Uint8Array(buf)
  }

  const webCrypto = typeof globalThis !== 'undefined' && (globalThis.crypto || globalThis.msCrypto)
  if (webCrypto && typeof webCrypto.getRandomValues === 'function') {
    const array = new Uint8Array(size)
    webCrypto.getRandomValues(array)
    return array
  }

  throw new Error('Secure random number generator is not available in this environment')
}

/**
 * Generates a random integer in `[l, r)`.
 *
 * @param {BN} l The lower bound of the random number.
 * @param {BN} r The upper bound of the random number.
 * @returns {BN} A cryptographically-random integer.
 */
export function randomInteger (l, r) {
  const range = r.sub(l)
  const size = Math.ceil(range.sub(new BN(1)).toString(16).length / 2)
  const v = new BN(toHex(randomBytes(size + 8)), 16)
  return v.mod(range).add(l)
}
