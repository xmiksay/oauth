// WebAuthn wire shapes (re-exported by `types.ts`): every binary value is base64url without
// padding.

export interface PasskeyDescriptor {
  type: 'public-key'
  id: string
  transports?: string[]
}

/** Server reply that starts a registration (`navigator.credentials.create`). */
export interface PasskeyCreationOptions {
  publicKey: {
    challenge: string
    rp: { id?: string; name: string }
    user: { id: string; name: string; displayName: string }
    pubKeyCredParams: { type: 'public-key'; alg: number }[]
    timeout?: number
    attestation?: AttestationConveyancePreference
    authenticatorSelection?: AuthenticatorSelectionCriteria
    excludeCredentials?: PasskeyDescriptor[]
  }
}

/** Server reply that starts an assertion (`navigator.credentials.get`). */
export interface PasskeyRequestOptions {
  publicKey: {
    challenge: string
    rpId?: string
    timeout?: number
    userVerification?: UserVerificationRequirement
    allowCredentials?: PasskeyDescriptor[]
  }
}

export interface PasskeyRegistration {
  id: string
  rawId: string
  type: 'public-key'
  response: { clientDataJSON: string; attestationObject: string; transports: string[] }
}

export interface PasskeyAssertion {
  id: string
  rawId: string
  type: 'public-key'
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle: string | null
  }
}
