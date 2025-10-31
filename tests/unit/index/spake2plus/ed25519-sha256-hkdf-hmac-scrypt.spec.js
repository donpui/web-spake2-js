/* global describe, it */
const assert = require('assert')

const spake2js = require('../../../../src')

describe('SPAKE2+ (Ed25519)', function () {
  const suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
  const mhf = { n: 16, r: 1, p: 1 }
  const kdf = { AAD: '' }
  const password = 'password'
  const salt = 'NaCl'
  const clientIdentity = 'client'
  const serverIdentity = 'server'

  it('completes an authenticated key exchange with verifier', async function () {
    const s = spake2js.spake2Plus({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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

  it('rejects incorrect password', async function () {
    const s = spake2js.spake2Plus({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
    const client = await s.startClient(clientIdentity, serverIdentity, 'incorrect', salt)
    const server = await s.startServer(clientIdentity, serverIdentity, verifier)

    const messageA = client.getMessage()
    const messageB = server.getMessage()

    const sharedSecretServer = server.finish(messageA)
    const sharedSecretClient = client.finish(messageB)

    const confirmationClient = sharedSecretClient.getConfirmation()
    assert.throws(() => sharedSecretServer.verify(confirmationClient))
  })

  it('rejects mismatched server identity', async function () {
    const s = spake2js.spake2Plus({ suite, mhf, kdf })

    const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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
