let TextEncoderCtor = typeof TextEncoder !== 'undefined' ? TextEncoder : undefined
let TextDecoderCtor = typeof TextDecoder !== 'undefined' ? TextDecoder : undefined

try {
  if (!TextEncoderCtor || !TextDecoderCtor) {
    const util = require('util')
    TextEncoderCtor = TextEncoderCtor || util.TextEncoder
    TextDecoderCtor = TextDecoderCtor || util.TextDecoder
  }
} catch (error) {
  // util not available (e.g. browser without modules) – handled below
}

const encoder = TextEncoderCtor ? new TextEncoderCtor() : null
const decoder = TextDecoderCtor ? new TextDecoderCtor() : null

function isBuffer (value) {
  return typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(value)
}

function toBytes (value) {
  if (value instanceof Uint8Array) return value
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (Array.isArray(value)) return Uint8Array.from(value)
  if (isBuffer(value)) return new Uint8Array(value)
  if (value === undefined || value === null) return new Uint8Array(0)
  if (typeof value === 'string') {
    if (encoder) return encoder.encode(value)
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'utf8'))
  }
  return Uint8Array.from(value)
}

function concatBytes (...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const out = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of arrays) {
    out.set(arr, offset)
    offset += arr.length
  }
  return out
}

function encodeLengthLE (length) {
  let value = BigInt(length)
  const out = new Uint8Array(8)
  for (let i = 0; i < 8; i++) {
    out[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return out
}

function concatLengthPrefixed (...values) {
  const pieces = []
  for (const value of values) {
    const bytes = toBytes(value)
    if (bytes.length === 0) continue
    pieces.push(encodeLengthLE(bytes.length))
    pieces.push(bytes)
  }
  return concatBytes(...pieces)
}

function equalBytes (a, b) {
  const aa = toBytes(a)
  const bb = toBytes(b)
  if (aa.length !== bb.length) return false
  let diff = 0
  for (let i = 0; i < aa.length; i++) {
    diff |= aa[i] ^ bb[i]
  }
  return diff === 0
}

function toHex (bytes) {
  const arr = toBytes(bytes)
  let out = ''
  for (let i = 0; i < arr.length; i++) {
    const hex = arr[i].toString(16).padStart(2, '0')
    out += hex
  }
  return out
}

function fromHex (hex) {
  const normalized = hex.trim().toLowerCase()
  const out = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(normalized.substr(i * 2, 2), 16)
  }
  return out
}

function bufferFrom (bytes) {
  const arr = toBytes(bytes)
  if (typeof Buffer !== 'undefined') return Buffer.from(arr)
  return Uint8Array.from(arr)
}

function bytesToString (bytes) {
  const arr = toBytes(bytes)
  if (decoder) return decoder.decode(arr)
  if (typeof Buffer !== 'undefined') return Buffer.from(arr).toString('utf8')
  throw new Error('TextDecoder is not available in this environment')
}

module.exports = {
  toBytes,
  concatBytes,
  concatLengthPrefixed,
  equalBytes,
  toHex,
  fromHex,
  bufferFrom,
  bytesToString
}
