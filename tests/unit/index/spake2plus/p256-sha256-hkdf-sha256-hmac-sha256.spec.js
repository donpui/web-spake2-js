/* global describe, it */
import assert from 'node:assert/strict'
import { Buffer } from 'buffer'

import {
  ClientSPAKE2PlusState,
  ServerSPAKE2PlusState
} from '../../../../src/index.js'

function toHex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function stripHex (hex) {
  return hex.replace(/\s+/g, '').replace(/^0x/, '')
}

describe('SPAKE2+ (P-256 test vector)', function () {
  const suite = 'P256-SHA256-HKDF-SHA256-HMAC-SHA256'
  const clientIdentity = 'client'
  const serverIdentity = 'server'
  const context = 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors'

  const vector = {
    w0: stripHex('0xbb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3'),
    w1: stripHex('0x7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba'),
    L: stripHex('0x04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd'),
    x: stripHex('0xd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539'),
    shareP: stripHex('0x04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727'),
    y: stripHex('0x717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3'),
    shareV: stripHex('0x04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048'),
    Z: stripHex('0x04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839'),
    V: stripHex('0x0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68'),
    transcript: stripHex('0x38000000000000005350414b45322b2d503235362d5348413235362d484b44462d5348413235362d484d41432d534841323536205465737420566563746f72730600000000000000636c69656e740600000000000000736572766572410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000004ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727410000000000000004c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048410000000000000004bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c4183941000000000000000458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b682000000000000000bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3'),
    hashTranscript: stripHex('0x4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29'),
    confirmKeyClient: stripHex('0x871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a'),
    confirmKeyServer: stripHex('0xccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680'),
    confirmClient: stripHex('0x926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527'),
    confirmServer: stripHex('0x9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68'),
    sharedKey: stripHex('0x0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7')
  }

  it('matches the published RFC 9383 vector', function () {
    const options = { suite, plus: true, kdf: { AAD: '' }, context }

    const clientState = ClientSPAKE2PlusState.load({
      options,
      x: vector.x,
      w0: vector.w0,
      w1: vector.w1,
      clientIdentity,
      serverIdentity
    })

    const serverState = ServerSPAKE2PlusState.load({
      options,
      y: vector.y,
      w0: vector.w0,
      L: Buffer.from(vector.L, 'hex'),
      clientIdentity,
      serverIdentity
    })

    const messageA = clientState.getMessage()
    assert.strictEqual(toHex(messageA), vector.shareP)

    const messageB = serverState.getMessage()
    assert.strictEqual(toHex(messageB), vector.shareV)

    const sharedSecretServer = serverState.finish(messageA)
    assert.strictEqual(toHex(sharedSecretServer.transcript), vector.transcript)
    assert.strictEqual(toHex(sharedSecretServer.hashTranscript), vector.hashTranscript)

    const sharedSecretClient = clientState.finish(messageB)
    assert.strictEqual(toHex(sharedSecretClient.transcript), vector.transcript)
    assert.strictEqual(toHex(sharedSecretClient.hashTranscript), vector.hashTranscript)

    assert.strictEqual(toHex(sharedSecretClient.K_confirmP), vector.confirmKeyClient)
    assert.strictEqual(toHex(sharedSecretServer.K_confirmP), vector.confirmKeyClient)
    assert.strictEqual(toHex(sharedSecretClient.K_confirmV), vector.confirmKeyServer)
    assert.strictEqual(toHex(sharedSecretServer.K_confirmV), vector.confirmKeyServer)

    const confirmationClient = sharedSecretClient.getConfirmation()
    assert.strictEqual(toHex(confirmationClient), vector.confirmClient)
    assert.doesNotThrow(() => sharedSecretServer.verify(confirmationClient))

    const confirmationServer = sharedSecretServer.getConfirmation()
    assert.strictEqual(toHex(confirmationServer), vector.confirmServer)
    assert.doesNotThrow(() => sharedSecretClient.verify(confirmationServer))

    assert.strictEqual(sharedSecretClient.toBuffer().toString('hex'), vector.sharedKey)
    assert.deepStrictEqual(sharedSecretClient.toBuffer(), sharedSecretServer.toBuffer())
  })
})
