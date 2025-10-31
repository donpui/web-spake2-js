import { spake2Plus } from '../../src/index.js'

const encoder = new TextEncoder()

function toHex (bytes) {
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}

async function run () {
  const options = {
    suite: 'P256-SHA256-HKDF-SHA256-HMAC-SHA256',
    mhf: { n: 32768, r: 8, p: 1 },
    kdf: { AAD: 'browser-demo' }
  }

  const password = 'correct horse battery staple'
  const salt = 'browser-salt'
  const clientId = 'client'
  const serverId = 'server'

  const s = spake2Plus(options)
  const verifier = await s.computeVerifier(password, salt, clientId, serverId)

  const client = await s.startClient(clientId, serverId, password, salt)
  const X = client.getMessage()

  const server = await s.startServer(clientId, serverId, verifier)
  const Y = server.getMessage()

  const serverSecret = server.finish(X)
  const clientSecret = client.finish(Y)

  serverSecret.verify(clientSecret.getConfirmation())
  const shared = clientSecret.toUint8Array()

  window.__spake2SharedKeyHex = toHex(shared)
}

window.runSpake2Demo = run
