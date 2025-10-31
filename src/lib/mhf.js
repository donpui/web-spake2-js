import scryptModule from 'scrypt-js'
import { toBytes } from './bytes.js'

const scryptFunc = typeof scryptModule === 'function'
  ? scryptModule
  : (typeof scryptModule?.scrypt === 'function' ? scryptModule.scrypt : scryptModule?.default)

/**
 * Use [scrypt](https://en.wikipedia.org/wiki/Scrypt) to hash the passphrase along with a given
 * salt and control parameters.
 *
 * @param {Buffer} passphrase The characters to be hashed.
 * @param {Buffer} salt The salt that protects against rainbow table attacks.
 * @param {object} options The options controlling the cost, block size and the parallelization.
 * @param {number} options.n The cost parameter for scrypt.
 * @param {number} options.r The block size parameter for scrypt.
 * @param {number} options.p The parallelization parameter for scrypt.
 * @param {number} [options.length] Desired derived key length in bytes. Defaults to 32.
 * @example
 * await scrypt(Buffer.from('password'), Buffer.from('NaCl'), { n: 1024, r: 8, p: 16 })
 * // returns <Buffer fd ba be 1c 9d 34 72 00 78 56 ...>
 * @returns {Promise<Buffer>} The hash value.
 */
export function scrypt (passphrase, salt, options = {}) {
  const { n, r, p, length } = options
  const dkLen = length !== undefined ? length : 32
  const passBytes = toBytes(passphrase)
  const saltBytes = toBytes(salt)

  return new Promise(function (resolve, reject) {
    if (typeof scryptFunc !== 'function') {
      return reject(new Error('scrypt function not available from scrypt-js module'))
    }

    try {
      const result = scryptFunc(passBytes, saltBytes, n, r, p, dkLen)
      if (result && typeof result.then === 'function') {
        result
          .then(key => resolve(toBytes(key)))
          .catch(reject)
        return
      }

      if (result) {
        resolve(toBytes(result))
        return
      }

      // Fallback to callback form if no result is returned.
      scryptFunc(passBytes, saltBytes, n, r, p, dkLen, function (error, _, key) {
        if (error) return reject(error)
        if (key) return resolve(toBytes(key))
        return reject(new Error('scrypt-js callback returned no key'))
      })
    } catch (error) {
      try {
        scryptFunc(passBytes, saltBytes, n, r, p, dkLen, function (callbackError, _, key) {
          if (callbackError) return reject(callbackError)
          if (key) return resolve(toBytes(key))
          return reject(new Error('scrypt-js callback returned no key'))
        })
      } catch (fallbackError) {
        reject(fallbackError || error)
      }
    }
  })
}
