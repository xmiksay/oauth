// Passkey ceremonies: server JSON options → browser WebAuthn calls → JSON results. Done by
// hand because `PublicKeyCredential.parseCreationOptionsFromJSON` isn't in every browser.
import type {
  PasskeyAssertion,
  PasskeyCreationOptions,
  PasskeyDescriptor,
  PasskeyRegistration,
  PasskeyRequestOptions,
} from '@/api/types'
import { b64urlDecode, b64urlEncode } from './base64url'

export { b64urlDecode, b64urlEncode } from './base64url'

/** The user dismissed the browser's passkey dialog (or it timed out / was aborted). */
export class PasskeyCancelled extends Error {
  constructor() {
    super('The passkey request was cancelled.')
    this.name = 'PasskeyCancelled'
  }
}

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function'
}

/** Whether the browser can offer passkeys in the username field's autofill. */
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (!passkeysSupported()) return false
  try {
    return (await window.PublicKeyCredential.isConditionalMediationAvailable?.()) === true
  } catch {
    return false
  }
}

function descriptor(d: PasskeyDescriptor): PublicKeyCredentialDescriptor {
  const out: PublicKeyCredentialDescriptor = { type: 'public-key', id: b64urlDecode(d.id) }
  if (d.transports) out.transports = d.transports as AuthenticatorTransport[]
  return out
}

export function creationOptions({ publicKey: o }: PasskeyCreationOptions): PublicKeyCredentialCreationOptions {
  return {
    ...o,
    challenge: b64urlDecode(o.challenge),
    user: { ...o.user, id: b64urlDecode(o.user.id) },
    excludeCredentials: (o.excludeCredentials ?? []).map(descriptor),
  }
}

export function requestOptions({ publicKey: o }: PasskeyRequestOptions): PublicKeyCredentialRequestOptions {
  return {
    ...o,
    challenge: b64urlDecode(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map(descriptor),
  }
}

export function registrationJSON(cred: PublicKeyCredential): PasskeyRegistration {
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: b64urlEncode(r.clientDataJSON),
      attestationObject: b64urlEncode(r.attestationObject),
      transports: r.getTransports?.() ?? [],
    },
  }
}

export function assertionJSON(cred: PublicKeyCredential): PasskeyAssertion {
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: b64urlEncode(r.clientDataJSON),
      authenticatorData: b64urlEncode(r.authenticatorData),
      signature: b64urlEncode(r.signature),
      userHandle: r.userHandle ? b64urlEncode(r.userHandle) : null,
    },
  }
}

/**
 * Browser WebAuthn failures as something the UI can show: a `PasskeyCancelled` (soft note),
 * a sentence (thrown as a string, like other UI errors), or the error unchanged.
 */
export function webauthnError(err: unknown): unknown {
  const name = typeof err === 'object' && err !== null ? (err as { name?: unknown }).name : null
  switch (name) {
    case 'NotAllowedError':
    case 'AbortError':
      return new PasskeyCancelled()
    case 'InvalidStateError':
      return 'This device already has a passkey for your account.'
    case 'SecurityError':
      return "Passkeys can't be used on this address."
    case 'NotSupportedError':
      return "This device doesn't support the kind of passkey required."
  }
  return err
}

async function ceremony(call: () => Promise<Credential | null>): Promise<PublicKeyCredential> {
  let cred: Credential | null
  try {
    cred = await call()
  } catch (err) {
    throw webauthnError(err)
  }
  if (!cred) throw new PasskeyCancelled()
  return cred as PublicKeyCredential
}

/** Registers a new passkey (`navigator.credentials.create`). */
export async function createPasskey(options: PasskeyCreationOptions): Promise<PasskeyRegistration> {
  const publicKey = creationOptions(options)
  return registrationJSON(await ceremony(() => navigator.credentials.create({ publicKey })))
}

export interface GetPasskeyInit {
  /** `conditional`: offer passkeys in the username field's autofill instead of a dialog. */
  mediation?: CredentialMediationRequirement
  signal?: AbortSignal
}

/** Signs a server challenge with a passkey (`navigator.credentials.get`). */
export async function getPasskey(
  options: PasskeyRequestOptions,
  init: GetPasskeyInit = {},
): Promise<PasskeyAssertion> {
  const publicKey = requestOptions(options)
  return assertionJSON(await ceremony(() => navigator.credentials.get({ ...init, publicKey })))
}
