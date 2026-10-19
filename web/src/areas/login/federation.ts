// Messages for the `error` the federation callback appends to `/login` (docs/api/authn.md).

export const UPSTREAM_FAILED = 'Sign-in with the identity provider failed. Please try again.'

/** `/login?error=…` without a tx: the callback couldn't tie the answer to a sign-in. */
export const UPSTREAM_EXPIRED =
  'Sign-in with the identity provider failed or the sign-in expired. Return to the application and try again.'

const MESSAGES: Record<string, string> = {
  upstream_failed: UPSTREAM_FAILED,
  upstream_no_email:
    'The identity provider did not share a verified email address, so no account could be created.',
  account_exists:
    'An account with this email address already exists. Sign in with your password or passkey, then link the identity provider under My Account → Security.',
  account_disabled: 'This account is disabled.',
  email_domain_not_allowed:
    'Your email domain is not allowed to create an account through this identity provider.',
  not_linked:
    'No account is linked to this identity. Sign in with your password or passkey and link it under My Account → Security.',
}

/** Step `link` answers (409) when the account can't take this identity. */
export const ALREADY_LINKED =
  'This account already has a linked identity at this provider. Sign in with it, or unlink it under My Account → Security first.'
export const LINK_UNAVAILABLE = 'The identity provider is no longer available. Sign in normally.'

export function upstreamErrorMessage(code: string): string {
  return MESSAGES[code] ?? UPSTREAM_FAILED
}

/** A plausible address to look up (discovery skips anything else). */
export function discoverable(email: string): boolean {
  const at = email.indexOf('@')
  return at > 0 && at < email.length - 1
}
