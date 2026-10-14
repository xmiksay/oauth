/** base64url without padding (RFC 4648 §5), the encoding of every WebAuthn binary on the wire. */
export function b64urlEncode(data: ArrayBuffer | ArrayBufferView): string {
  const bytes = ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Inverse of `b64urlEncode`; tolerates padding, throws on anything that isn't base64url. */
export function b64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  const bare = text.replace(/=+$/, '')
  if (!/^[A-Za-z0-9_-]*$/.test(bare)) throw new TypeError('invalid base64url')
  const b64 = bare.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
