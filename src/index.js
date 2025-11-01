import BN from 'bn.js'

import { cipherSuites } from './lib/cipher-suites.js'
import { randomInteger } from './lib/random.js'
import {
  toBytes,
  concatLengthPrefixed,
  equalBytes,
  toHex,
  fromHex,
  bufferFrom
} from './lib/bytes.js'

function encodeScalar (scalar, length) {
  return scalar.toArrayLike(Uint8Array, 'be', length)
}

function getCipherSuite (name) {
  const cipherSuite = cipherSuites[name]
  if (!cipherSuite) throw new Error('undefined cipher suite')
  return cipherSuite
}

function getContextBytes (options, cipherSuite) {
  if (!options.plus) return new Uint8Array(0)
  if (options.context !== undefined) return toBytes(options.context)
  const defaultContext = cipherSuite.suiteIds?.spake2Plus
  return defaultContext ? toBytes(defaultContext) : new Uint8Array(0)
}

function buildSpake2Transcript ({ clientIdentity, serverIdentity, clientMessage, serverMessage, sharedKey, w, cipherSuite }) {
  const wEncoded = encodeScalar(w, cipherSuite.scalarLength)
  return concatLengthPrefixed(
    clientIdentity ? toBytes(clientIdentity) : new Uint8Array(0),
    serverIdentity ? toBytes(serverIdentity) : new Uint8Array(0),
    clientMessage,
    serverMessage,
    sharedKey,
    wEncoded
  )
}

function buildSpake2PlusTranscript ({ context, clientIdentity, serverIdentity, curve, clientMessage, serverMessage, Z, V, w0, cipherSuite }) {
  const MEncoded = curve.encodePoint(curve.M)
  const NEncoded = curve.encodePoint(curve.N)
  const ZEncoded = curve.encodePoint(Z)
  const VEncoded = curve.encodePoint(V)
  const w0Encoded = encodeScalar(w0, cipherSuite.scalarLength)
  return concatLengthPrefixed(
    context,
    clientIdentity ? toBytes(clientIdentity) : new Uint8Array(0),
    serverIdentity ? toBytes(serverIdentity) : new Uint8Array(0),
    MEncoded,
    NEncoded,
    clientMessage,
    serverMessage,
    ZEncoded,
    VEncoded,
    w0Encoded
  )
}

function constantTimeEqual (a, b) {
  return equalBytes(a, b)
}

function computeMhfLength (cipherSuite, multiplier = 1) {
  const minBytes = Math.ceil((cipherSuite.scalarBitLength + 64) / 8)
  return multiplier * minBytes
}

class SPAKE2 {
  constructor (options, cipherSuite) {
    const normalizedOptions = { ...options }
    if (!normalizedOptions.kdf) normalizedOptions.kdf = {}
    if (!normalizedOptions.mhf) normalizedOptions.mhf = {}
    normalizedOptions.plus = options.plus

    if (normalizedOptions.plus && normalizedOptions.context === undefined) {
      const defaultContext = cipherSuite.suiteIds?.spake2Plus
      if (defaultContext) normalizedOptions.context = defaultContext
    }

    this.options = normalizedOptions
    this.cipherSuite = cipherSuite
  }

  async startClient (clientIdentity, serverIdentity, password, salt = new Uint8Array(0)) {
    const { options, cipherSuite } = this
    const { p } = cipherSuite.curve
    const x = randomInteger(new BN(0), p)

    if (!options.plus) {
      const w = await this._computeW(password, salt)
      return new ClientSPAKE2State({ clientIdentity, serverIdentity, w, x, options, cipherSuite })
    }

    const { w0, w1 } = await this._computeW0W1(clientIdentity, serverIdentity, password, salt)
    return new ClientSPAKE2PlusState({ clientIdentity, serverIdentity, w0, w1, x, options, cipherSuite })
  }

  async startServer (clientIdentity, serverIdentity, verifier) {
    const { options, cipherSuite } = this
    const { p } = cipherSuite.curve
    const y = randomInteger(new BN(0), p)

    if (!options.plus) {
      const w = new BN(toHex(verifier), 16)
      return new ServerSPAKE2State({ clientIdentity, serverIdentity, w, y, options, cipherSuite })
    }

    const { curve } = cipherSuite
    const w0 = new BN(toHex(verifier.w0), 16).mod(p)
    const L = curve.decodePoint(verifier.L)
    return new ServerSPAKE2PlusState({ clientIdentity, serverIdentity, w0, L, y, options, cipherSuite })
  }

  async computeVerifier (password, salt, clientIdentity, serverIdentity) {
    const { cipherSuite } = this
    if (!this.options.plus) {
      const w = await this._computeW(password, salt)
      return encodeScalar(w, cipherSuite.scalarLength)
    }

    const { w0, w1 } = await this._computeW0W1(clientIdentity, serverIdentity, password, salt)
    const L = cipherSuite.curve.P.mul(w1)
    return {
      w0: encodeScalar(w0, cipherSuite.scalarLength),
      L: cipherSuite.curve.encodePoint(L)
    }
  }

  async _computeW (password, salt) {
    const { cipherSuite, options } = this
    const { p } = cipherSuite.curve
    const length = computeMhfLength(cipherSuite)
    const mhfOptions = { ...options.mhf, length }
    const derived = await cipherSuite.mhf(toBytes(password), toBytes(salt), mhfOptions)
    return new BN(toHex(derived), 16).mod(p)
  }

  async _computeW0W1 (clientIdentity, serverIdentity, password, salt) {
    const { cipherSuite, options } = this
    const { p } = cipherSuite.curve
    const length = computeMhfLength(cipherSuite, 2)
    const mhfOptions = { ...options.mhf, length }
    const input = concatLengthPrefixed(
      password,
      clientIdentity || '',
      serverIdentity || ''
    )
    const derived = await cipherSuite.mhf(input, toBytes(salt), mhfOptions)
    const half = Math.floor(derived.length / 2)
    const w0 = new BN(toHex(derived.subarray(0, half)), 16).mod(p)
    const w1 = new BN(toHex(derived.subarray(half)), 16).mod(p)
    return { w0, w1 }
  }
}

class ClientSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, x, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w = w
  }

  getMessage () {
    const { cipherSuite, x, w } = this
    const { curve } = cipherSuite
    const T = curve.P.mul(x).add(curve.M.mul(w))
    this.T = T
    const message = curve.encodePoint(T)
    this.clientMessage = message
    return message
  }

  finish (incomingMessage) {
    const { cipherSuite, options, clientIdentity, serverIdentity, T, w, x, clientMessage } = this
    if (!T || !clientMessage) throw new Error('getMessage method needs to be called before this method')

    const { curve } = cipherSuite
    const { h } = curve
    const S = curve.decodePoint(incomingMessage)
    const serverMessage = curve.encodePoint(S)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')

    const base = S.add(curve.N.mul(w).neg())
    const scalar = x.mul(h).umod(curve.p)
    const K = base.mul(scalar)
    const sharedKey = curve.encodePoint(K)

    const transcript = buildSpake2Transcript({
      clientIdentity,
      serverIdentity,
      clientMessage,
      serverMessage,
      sharedKey,
      w,
      cipherSuite
    })

    return new ClientSharedSecret({
      options,
      cipherSuite,
      transcript,
      clientMessage,
      serverMessage
    })
  }

  save () {
    const { options, x, w, clientIdentity, serverIdentity } = this
    return {
      options,
      x: x.toString('hex'),
      w: w.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, x, w, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSPAKE2State({
      options,
      x: new BN(x, 16),
      w: new BN(w, 16),
      clientIdentity,
      serverIdentity,
      cipherSuite
    })
  }
}

class ServerSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, y, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w = w
  }

  getMessage () {
    const { cipherSuite, y, w } = this
    const { curve } = cipherSuite
    const S = curve.P.mul(y).add(curve.N.mul(w))
    this.S = S
    const message = curve.encodePoint(S)
    this.serverMessage = message
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite, clientIdentity, serverIdentity, S, w, y, serverMessage } = this
    if (!S || !serverMessage) throw new Error('getMessage method needs to be called before this method')

    const { curve } = cipherSuite
    const { h } = curve
    const T = curve.decodePoint(incomingMessage)
    const clientMessage = curve.encodePoint(T)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')

    const base = T.add(curve.M.mul(w).neg())
    const scalar = y.mul(h).umod(curve.p)
    const K = base.mul(scalar)
    const sharedKey = curve.encodePoint(K)

    const transcript = buildSpake2Transcript({
      clientIdentity,
      serverIdentity,
      clientMessage,
      serverMessage,
      sharedKey,
      w,
      cipherSuite
    })

    return new ServerSharedSecret({
      options,
      cipherSuite,
      transcript,
      clientMessage,
      serverMessage
    })
  }

  save () {
    const { options, y, w, clientIdentity, serverIdentity } = this
    return {
      options,
      y: y.toString('hex'),
      w: w.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, y, w, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    return new ServerSPAKE2State({
      options,
      y: new BN(y, 16),
      w: new BN(w, 16),
      clientIdentity,
      serverIdentity,
      cipherSuite
    })
  }
}

class ClientSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, w1, x, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w0 = w0
    this.w1 = w1
  }

  getMessage () {
    const { cipherSuite, x, w0 } = this
    const { curve } = cipherSuite
    const T = curve.P.mul(x).add(curve.M.mul(w0))
    this.T = T
    const message = curve.encodePoint(T)
    this.clientMessage = message
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite, clientIdentity, serverIdentity, T, w0, w1, x, clientMessage } = this
    if (!T || !clientMessage) throw new Error('getMessage method needs to be called before this method')

    const { curve } = cipherSuite
    const { h } = curve
    const S = curve.decodePoint(incomingMessage)
    const serverMessage = curve.encodePoint(S)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')

    const base = S.add(curve.N.mul(w0).neg())
    const scalarZ = x.mul(h).umod(curve.p)
    const scalarV = w1.mul(h).umod(curve.p)
    const Z = base.mul(scalarZ)
    const V = base.mul(scalarV)

    const context = getContextBytes(options, cipherSuite)
    const transcript = buildSpake2PlusTranscript({
      context,
      clientIdentity,
      serverIdentity,
      curve,
      clientMessage,
      serverMessage,
      Z,
      V,
      w0,
      cipherSuite
    })

    return new ClientSharedSecret({
      options,
      cipherSuite,
      transcript,
      clientMessage,
      serverMessage
    })
  }

  save () {
    const { options, x, w0, w1, clientIdentity, serverIdentity } = this
    return {
      options,
      x: x.toString('hex'),
      w0: w0.toString('hex'),
      w1: w1.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, x, w0, w1, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSPAKE2PlusState({
      options,
      x: new BN(x, 16),
      w0: new BN(w0, 16),
      w1: new BN(w1, 16),
      clientIdentity,
      serverIdentity,
      cipherSuite
    })
  }
}

class ServerSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, L, y, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w0 = w0
    this.L = L
  }

  getMessage () {
    const { cipherSuite, y, w0 } = this
    const { curve } = cipherSuite
    const S = curve.P.mul(y).add(curve.N.mul(w0))
    this.S = S
    const message = curve.encodePoint(S)
    this.serverMessage = message
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite, clientIdentity, serverIdentity, S, w0, L, y, serverMessage } = this
    if (!S || !serverMessage) throw new Error('getMessage method needs to be called before this method')

    const { curve } = cipherSuite
    const { h } = curve
    const T = curve.decodePoint(incomingMessage)
    const clientMessage = curve.encodePoint(T)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')

    const base = T.add(curve.M.mul(w0).neg())
    const scalar = y.mul(h).umod(curve.p)
    const Z = base.mul(scalar)
    const V = L.mul(scalar)

    const context = getContextBytes(options, cipherSuite)
    const transcript = buildSpake2PlusTranscript({
      context,
      clientIdentity,
      serverIdentity,
      curve,
      clientMessage,
      serverMessage,
      Z,
      V,
      w0,
      cipherSuite
    })

    return new ServerSharedSecret({
      options,
      cipherSuite,
      transcript,
      clientMessage,
      serverMessage
    })
  }

  save () {
    const { options, y, w0, L, clientIdentity, serverIdentity, cipherSuite } = this
    return {
      options,
      y: y.toString('hex'),
      w0: w0.toString('hex'),
      L: toHex(cipherSuite.curve.encodePoint(L)),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, y, w0, L, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    const pointBytes = typeof L === 'string' ? fromHex(L) : toBytes(L)
    return new ServerSPAKE2PlusState({
      options,
      y: new BN(y, 16),
      w0: new BN(w0, 16),
      L: cipherSuite.curve.decodePoint(pointBytes),
      clientIdentity,
      serverIdentity,
      cipherSuite
    })
  }
}

class ClientSharedSecret {
  constructor ({ options, transcript, cipherSuite, clientMessage, serverMessage }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.transcript = transcript
    this.clientMessage = clientMessage
    this.serverMessage = serverMessage

    if (options.plus && (!clientMessage || !serverMessage)) {
      throw new Error('client and server messages are required for SPAKE2+ shared secrets')
    }

    const hashTranscript = cipherSuite.hash(transcript)
    this.hashTranscript = hashTranscript

    const aad = options.kdf.AAD || ''
    const salt = new Uint8Array(0)
    const hashLength = cipherSuite.hashLength

    if (options.plus) {
      const confirmLength = hashLength * 2
      const confirmationKeys = cipherSuite.kdf(salt, hashTranscript, 'ConfirmationKeys' + aad, confirmLength)
      const half = Math.floor(confirmationKeys.length / 2)
      this.K_confirmP = confirmationKeys.subarray(0, half)
      this.K_confirmV = confirmationKeys.subarray(half)
      this.sharedKey = cipherSuite.kdf(salt, hashTranscript, 'SharedKey' + aad, hashLength)
      return
    }

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const confirmationKeys = cipherSuite.kdf(salt, this.Ka, 'ConfirmationKeys' + aad, hashLength)
    const half = Math.floor(confirmationKeys.length / 2)
    this.KcA = confirmationKeys.subarray(0, half)
    this.KcB = confirmationKeys.subarray(half)
  }

  getConfirmation () {
    const { cipherSuite, options, transcript, serverMessage, KcA, K_confirmP } = this
    if (options.plus) {
      return cipherSuite.mac(serverMessage, K_confirmP)
    }
    return cipherSuite.mac(transcript, KcA)
  }

  verify (incomingConfirmation) {
    const { cipherSuite, options, transcript, clientMessage, KcB, K_confirmV } = this
    if (options.plus) {
      const expected = cipherSuite.mac(clientMessage, K_confirmV)
      if (!constantTimeEqual(expected, incomingConfirmation)) {
        throw new Error('invalid confirmation from server')
      }
      return
    }

    const expected = cipherSuite.mac(transcript, KcB)
    if (!constantTimeEqual(expected, incomingConfirmation)) {
      throw new Error('invalid confirmation from server')
    }
  }

  toBuffer () {
    return bufferFrom(this.hashTranscript)
  }

  toUint8Array () {
    return this.hashTranscript.slice()
  }

  toKeBuffer () {
    const bytes = this.options.plus ? this.sharedKey : this.Ke
    return bufferFrom(bytes)
  }

  getTranscriptHash () {
    return this.hashTranscript.slice()
  }

  save () {
    const { options, transcript, clientMessage, serverMessage } = this
    const saveData = {
      options,
      transcript: toHex(transcript)
    }

    if (options.plus) {
      saveData.clientMessage = toHex(clientMessage)
      saveData.serverMessage = toHex(serverMessage)
    }

    return saveData
  }

  static load ({ options, transcript, clientMessage, serverMessage }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSharedSecret({
      options,
      transcript: typeof transcript === 'string' ? fromHex(transcript) : toBytes(transcript),
      clientMessage: clientMessage ? (typeof clientMessage === 'string' ? fromHex(clientMessage) : toBytes(clientMessage)) : undefined,
      serverMessage: serverMessage ? (typeof serverMessage === 'string' ? fromHex(serverMessage) : toBytes(serverMessage)) : undefined,
      cipherSuite
    })
  }
}

class ServerSharedSecret {
  constructor ({ options, transcript, cipherSuite, clientMessage, serverMessage }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.transcript = transcript
    this.clientMessage = clientMessage
    this.serverMessage = serverMessage

    if (options.plus && (!clientMessage || !serverMessage)) {
      throw new Error('client and server messages are required for SPAKE2+ shared secrets')
    }

    const hashTranscript = cipherSuite.hash(transcript)
    this.hashTranscript = hashTranscript

    const aad = options.kdf.AAD || ''
    const salt = new Uint8Array(0)

    const hashLength = cipherSuite.hashLength

    if (options.plus) {
      const confirmLength = hashLength * 2
      const confirmationKeys = cipherSuite.kdf(salt, hashTranscript, 'ConfirmationKeys' + aad, confirmLength)
      const half = Math.floor(confirmationKeys.length / 2)
      this.K_confirmP = confirmationKeys.subarray(0, half)
      this.K_confirmV = confirmationKeys.subarray(half)
      this.sharedKey = cipherSuite.kdf(salt, hashTranscript, 'SharedKey' + aad, hashLength)
      return
    }

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const confirmationKeys = cipherSuite.kdf(salt, this.Ka, 'ConfirmationKeys' + aad, hashLength)
    const half = Math.floor(confirmationKeys.length / 2)
    this.KcA = confirmationKeys.subarray(0, half)
    this.KcB = confirmationKeys.subarray(half)
  }

  getConfirmation () {
    const { cipherSuite, options, clientMessage, transcript, K_confirmV, KcB } = this
    if (options.plus) {
      return cipherSuite.mac(clientMessage, K_confirmV)
    }
    return cipherSuite.mac(transcript, KcB)
  }

  verify (incomingConfirmation) {
    const { cipherSuite, options, serverMessage, transcript, K_confirmP, KcA } = this
    if (options.plus) {
      const expected = cipherSuite.mac(serverMessage, K_confirmP)
      if (!constantTimeEqual(expected, incomingConfirmation)) {
        throw new Error('invalid confirmation from client')
      }
      return
    }

    const expected = cipherSuite.mac(transcript, KcA)
    if (!constantTimeEqual(expected, incomingConfirmation)) {
      throw new Error('invalid confirmation from client')
    }
  }

  toBuffer () {
    return bufferFrom(this.hashTranscript)
  }

  toUint8Array () {
    return this.hashTranscript.slice()
  }

  toKeBuffer () {
    const bytes = this.options.plus ? this.sharedKey : this.Ke
    return bufferFrom(bytes)
  }

  getTranscriptHash () {
    return this.hashTranscript.slice()
  }

  save () {
    const { options, transcript, clientMessage, serverMessage } = this
    const saveData = {
      options,
      transcript: toHex(transcript)
    }

    if (options.plus) {
      saveData.clientMessage = toHex(clientMessage)
      saveData.serverMessage = toHex(serverMessage)
    }

    return saveData
  }

  static load ({ options, transcript, clientMessage, serverMessage }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
    const cipherSuite = getCipherSuite(suite)
    return new ServerSharedSecret({
      options,
      transcript: typeof transcript === 'string' ? fromHex(transcript) : toBytes(transcript),
      clientMessage: clientMessage ? (typeof clientMessage === 'string' ? fromHex(clientMessage) : toBytes(clientMessage)) : undefined,
      serverMessage: serverMessage ? (typeof serverMessage === 'string' ? fromHex(serverMessage) : toBytes(serverMessage)) : undefined,
      cipherSuite
    })
  }
}

function spake2Factory (options = {}, plus = false) {
  let { suite } = options
  if (suite === undefined) suite = 'ED25519-SHA256-HKDF-SHA256-HMAC-SHA256'
  const cipherSuite = getCipherSuite(suite)
  options.plus = plus
  return new SPAKE2(options, cipherSuite)
}

const spake2 = options => spake2Factory(options, false)
const spake2Plus = options => spake2Factory(options, true)

export {
  spake2,
  spake2Plus,
  SPAKE2,
  ClientSPAKE2State,
  ServerSPAKE2State,
  ClientSPAKE2PlusState,
  ServerSPAKE2PlusState,
  ClientSharedSecret,
  ServerSharedSecret
}

export default {
  spake2,
  spake2Plus,
  SPAKE2,
  ClientSPAKE2State,
  ServerSPAKE2State,
  ClientSPAKE2PlusState,
  ServerSPAKE2PlusState,
  ClientSharedSecret,
  ServerSharedSecret
}
