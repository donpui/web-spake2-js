/* global describe, it */
import assert from 'node:assert/strict'

import { spake2 as createSpake2 } from '../../../../src/index.js'

describe('SPAKE2 (Ed25519)', function () {
  const suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
  const mhf = { n: 16, r: 1, p: 1 }
  const kdf = { AAD: '' }
  const password = 'password'
  const salt = 'NaCl'
  const clientIdentity = 'client'
  const serverIdentity = 'server'

  it('completes an authenticated key exchange', async function () {
    const s = createSpake2({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt)
    const client = await s.startClient(clientIdentity, serverIdentity, password, salt)
    const server = await s.startServer(clientIdentity, serverIdentity, verifier)

    const messageA = client.getMessage()
    const messageB = server.getMessage()

    const sharedSecretServer = server.finish(messageA)
    const sharedSecretClient = client.finish(messageB)

    const confirmationClient = sharedSecretClient.getConfirmation()
    assert.doesNotThrow(() => sharedSecretServer.verify(confirmationClient))

    const confirmationServer = sharedSecretServer.getConfirmation()
    assert.doesNotThrow(() => sharedSecretClient.verify(confirmationServer))

    assert.deepStrictEqual(sharedSecretClient.toBuffer(), sharedSecretServer.toBuffer())
  })

  it('fails when the client password is incorrect', async function () {
    const s = createSpake2({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt)
    const client = await s.startClient(clientIdentity, serverIdentity, 'wrong_password', salt)
    const server = await s.startServer(clientIdentity, serverIdentity, verifier)

    const messageA = client.getMessage()
    const messageB = server.getMessage()

    server.finish(messageA)
    const sharedSecretClient = client.finish(messageB)
    const confirmationClient = sharedSecretClient.getConfirmation()

    const sharedSecretServer = server.finish(messageA)
    assert.throws(() => sharedSecretServer.verify(confirmationClient))
  })

  it('fails when identities do not match', async function () {
    const s = createSpake2({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt)
    const client = await s.startClient(clientIdentity, serverIdentity, password, salt)
    const server = await s.startServer(clientIdentity, 'other-server', verifier)

    const messageA = client.getMessage()
    const messageB = server.getMessage()

    const sharedSecretServer = server.finish(messageA)
    const sharedSecretClient = client.finish(messageB)

    const confirmationServer = sharedSecretServer.getConfirmation()
    assert.throws(() => sharedSecretClient.verify(confirmationServer))
  })
})
