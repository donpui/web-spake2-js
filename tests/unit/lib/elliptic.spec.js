/* global describe, it */
import assert from 'node:assert/strict'

import { CURVES, Elliptic } from '../../../src/lib/elliptic.js'

describe('lib/elliptic.js', function () {
  describe('Elliptic', function () {
    it('TODO', async function () {
      const ec = new Elliptic(CURVES.ed25519)
      // Use the internal APIs to check if the points are on the curve
      assert(ec.ec.validate(ec.M))
      assert(ec.ec.validate(ec.N))

      // TODO: encode->decode = self
    })
  })
})
