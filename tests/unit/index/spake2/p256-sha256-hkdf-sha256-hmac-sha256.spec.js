/* global describe, it */
import assert from 'assert'
import { Buffer } from 'buffer'

import {
  ClientSPAKE2State,
  ServerSPAKE2State
} from '../../../../src/index.js'

function toHex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function stripHex (hex) {
  return hex.replace(/\s+/g, '').replace(/^0x/, '')
}

describe('SPAKE2 (P-256 test vector)', function () {
  const suite = 'P256-SHA256-HKDF-SHA256-HMAC-SHA256'
  const identityA = 'server'
  const identityB = 'client'

  const vector = {
    w: stripHex('0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f'),
    x: stripHex('0x43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729'),
    y: stripHex('0xdcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be'),
    shareP: stripHex('0x04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c'),
    shareV: stripHex('0x0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7'),
    sharedPoint: stripHex('0x0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325'),
    transcript: stripHex('0x06000000000000007365727665720600000000000000636c69656e74410000000000000004a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c41000000000000000406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b741000000000000000412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d332520000000000000002ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f'),
    hashTranscript: stripHex('0x0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b'),
    confirmationClient: stripHex('0x58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0'),
    confirmationServer: stripHex('0xd3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b'),
    sharedSecret: stripHex('0x0e0672dc86f8e45565d338b0540abe69')
  }

  it('matches the published RFC 9382 vector', function () {
    const options = { suite, kdf: { AAD: '' } }

    const clientState = ClientSPAKE2State.load({
      options,
      x: vector.x,
      w: vector.w,
      clientIdentity: identityA,
      serverIdentity: identityB
    })
    const serverState = ServerSPAKE2State.load({
      options,
      y: vector.y,
      w: vector.w,
      clientIdentity: identityA,
      serverIdentity: identityB
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

    const confirmationClient = sharedSecretClient.getConfirmation()
    assert.strictEqual(toHex(confirmationClient), vector.confirmationClient)
    assert.doesNotThrow(() => sharedSecretServer.verify(confirmationClient))

    const confirmationServer = sharedSecretServer.getConfirmation()
    assert.strictEqual(toHex(confirmationServer), vector.confirmationServer)
    assert.doesNotThrow(() => sharedSecretClient.verify(confirmationServer))

    assert.strictEqual(sharedSecretClient.toBuffer().toString('hex'), vector.sharedSecret)
    assert.deepStrictEqual(sharedSecretClient.toBuffer(), sharedSecretServer.toBuffer())
  })
})
