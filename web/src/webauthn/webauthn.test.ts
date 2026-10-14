import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ASSERTION_JSON,
  CREATION_OPTIONS,
  REGISTRATION_JSON,
  REQUEST_OPTIONS,
  domError,
  fakeAssertion,
  stubWebAuthn,
} from '@/test/helpers'
import {
  PasskeyCancelled,
  assertionJSON,
  b64urlDecode,
  b64urlEncode,
  conditionalMediationAvailable,
  createPasskey,
  creationOptions,
  getPasskey,
  passkeysSupported,
  requestOptions,
  webauthnError,
} from '.'

afterEach(() => vi.unstubAllGlobals())

const arr = (v: BufferSource | undefined) =>
  Array.from(new Uint8Array(ArrayBuffer.isView(v) ? v.buffer : (v as ArrayBuffer)))

describe('base64url', () => {
  it('encodes without padding using the URL alphabet', () => {
    expect(b64urlEncode(new Uint8Array([0xfb, 0xff]))).toBe('-_8')
    expect(b64urlEncode(new Uint8Array([1, 2, 3]).buffer)).toBe('AQID')
    expect(b64urlEncode(new Uint8Array(0))).toBe('')
  })

  it('round-trips every byte value and views into a larger buffer', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i)
    expect(Array.from(b64urlDecode(b64urlEncode(all)))).toEqual(Array.from(all))
    const view = new Uint8Array([9, 1, 2, 9]).subarray(1, 3)
    expect(b64urlEncode(view)).toBe('AQI')
  })

  it('decodes padded input and rejects other alphabets', () => {
    expect(Array.from(b64urlDecode('AQ=='))).toEqual([1])
    expect(() => b64urlDecode('a+b/')).toThrow(TypeError)
  })
})

describe('option conversion', () => {
  it('decodes the creation challenge, user id and excluded credentials', () => {
    const o = creationOptions({
      publicKey: {
        ...CREATION_OPTIONS.publicKey,
        attestation: 'none',
        excludeCredentials: [{ type: 'public-key', id: 'AQI', transports: ['usb'] }],
      },
    })
    expect(arr(o.challenge)).toEqual([1, 2, 3])
    expect(arr(o.user.id)).toEqual([4, 5])
    expect(o.user.name).toBe('ann@example.com')
    expect(o.rp).toEqual({ id: 'contoso.example', name: 'Contoso' })
    expect(o.attestation).toBe('none')
    expect(arr(o.excludeCredentials?.[0]?.id)).toEqual([1, 2])
    expect(o.excludeCredentials?.[0]?.transports).toEqual(['usb'])
  })

  it('decodes the request challenge and allowed credentials (empty = discoverable)', () => {
    const o = requestOptions({
      publicKey: { ...REQUEST_OPTIONS.publicKey, allowCredentials: [{ type: 'public-key', id: 'BQ' }] },
    })
    expect(arr(o.challenge)).toEqual([1, 2, 3])
    expect(o.rpId).toBe('contoso.example')
    expect(arr(o.allowCredentials?.[0]?.id)).toEqual([5])
    expect(requestOptions(REQUEST_OPTIONS).allowCredentials).toEqual([])
  })
})

describe('ceremonies', () => {
  it('detects support and conditional mediation', async () => {
    expect(passkeysSupported()).toBe(false)
    expect(await conditionalMediationAvailable()).toBe(false)
    stubWebAuthn(true)
    expect(passkeysSupported()).toBe(true)
    expect(await conditionalMediationAvailable()).toBe(true)
  })

  it('creates a passkey and serializes the attestation', async () => {
    const { create } = stubWebAuthn()
    expect(await createPasskey(CREATION_OPTIONS)).toEqual(REGISTRATION_JSON)
    expect(arr(create.mock.calls[0]?.[0]?.publicKey?.challenge)).toEqual([1, 2, 3])
  })

  it('passes mediation and signal through and serializes the assertion', async () => {
    const { get } = stubWebAuthn()
    const signal = new AbortController().signal
    expect(await getPasskey(REQUEST_OPTIONS, { mediation: 'conditional', signal })).toEqual(
      ASSERTION_JSON,
    )
    expect(get.mock.calls[0]?.[0]).toMatchObject({ mediation: 'conditional', signal })
  })

  it('sends a missing user handle as null', () => {
    const cred = fakeAssertion(null) as unknown as PublicKeyCredential
    expect(assertionJSON(cred).response.userHandle).toBeNull()
  })

  it('turns a dismissed dialog (or no credential) into PasskeyCancelled', async () => {
    const { get, create } = stubWebAuthn()
    get.mockRejectedValueOnce(domError('NotAllowedError'))
    await expect(getPasskey(REQUEST_OPTIONS)).rejects.toBeInstanceOf(PasskeyCancelled)
    create.mockResolvedValueOnce(null)
    await expect(createPasskey(CREATION_OPTIONS)).rejects.toBeInstanceOf(PasskeyCancelled)
  })

  it('maps other browser failures to sentences and passes the rest through', () => {
    expect(webauthnError(domError('AbortError'))).toBeInstanceOf(PasskeyCancelled)
    expect(webauthnError(domError('InvalidStateError'))).toMatch(/already has a passkey/)
    expect(webauthnError(domError('SecurityError'))).toMatch(/can't be used/)
    const other = new TypeError('x')
    expect(webauthnError(other)).toBe(other)
  })
})
