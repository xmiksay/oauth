import { describe, expect, it } from 'vitest'
import { useLoginFlow } from './useLoginFlow'
import {
  ALREADY_LINKED,
  LINK_UNAVAILABLE,
  UPSTREAM_FAILED,
  upstreamErrorMessage,
} from './federation'
import { deps, err, view } from './flowFixtures'

const ENTRA = { id: 'idp1', name: 'Entra' }
const UPSTREAM = 'https://login.example.com/authorize?state=s'

describe('useLoginFlow federation', () => {
  it('starts a federated sign-in with a full-page redirect', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password', { idps: [ENTRA] }))
    d.api.federation.mockResolvedValue({ redirect: UPSTREAM })
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.federate(ENTRA)
    expect(d.api.federation).toHaveBeenCalledWith('tx-1', 'idp1')
    expect(d.navigate).toHaveBeenCalledWith(UPSTREAM)
    expect([flow.phase.value, flow.federating.value]).toEqual(['redirecting', ENTRA])
  })

  it('stays at the password step when the provider cannot be reached', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password', { idps: [ENTRA] }))
    d.api.federation.mockRejectedValue(err(502, 'upstream_failed'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.federate(ENTRA)
    expect(d.navigate).not.toHaveBeenCalled()
    expect([flow.phase.value, flow.federating.value, flow.error.value]).toEqual([
      'step',
      null,
      UPSTREAM_FAILED,
    ])
  })

  it('redirects to the hinted provider right away, once', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password', { idp_hint: ENTRA }))
    d.api.federation.mockRejectedValue(err(409, 'wrong_step'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    // The 409 reloaded the view; the reload must not start another redirect.
    expect(d.api.get).toHaveBeenCalledTimes(2)
    expect(d.api.federation).toHaveBeenCalledTimes(1)
    expect(flow.federating.value).toBeNull()
  })

  it('never auto-redirects after an upstream error, and shows it once', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password', { idp_hint: ENTRA }))
    const flow = useLoginFlow('tx-1', d.deps, 'account_exists')
    await flow.load()
    expect(d.api.federation).not.toHaveBeenCalled()
    expect(flow.error.value).toBe(upstreamErrorMessage('account_exists'))
    await flow.load()
    expect(flow.error.value).toBeNull()
  })

  it('maps upstream error codes, unknown ones to a plain failure', () => {
    expect(upstreamErrorMessage('upstream_no_email')).toMatch(/verified email address/)
    expect(upstreamErrorMessage('not_linked')).toMatch(/^No account is linked/)
    expect(upstreamErrorMessage('account_disabled')).toBe('This account is disabled.')
    expect(upstreamErrorMessage('email_domain_not_allowed')).toBe(
      'Your email domain is not allowed to create an account through this identity provider.',
    )
    expect(upstreamErrorMessage('nonsense')).toBe(UPSTREAM_FAILED)
  })

  it('discovers the provider of an email domain once per address', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(
      view('password', { features: { password_reset: false, federation: true } }),
    )
    d.api.discover.mockResolvedValueOnce({ idp: ENTRA }).mockResolvedValueOnce({})
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.discover('ann')
    expect(d.api.discover).not.toHaveBeenCalled()
    await flow.discover(' ann@contoso.com ')
    await flow.discover('ann@contoso.com')
    expect(d.api.discover).toHaveBeenCalledTimes(1)
    expect(d.api.discover).toHaveBeenCalledWith('tx-1', 'ann@contoso.com')
    expect(flow.suggestion.value).toEqual(ENTRA)
    await flow.discover('ann@gmail.com')
    expect(flow.suggestion.value).toBeNull()
  })

  it('discovers nothing without federation and ignores discovery failures', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.discover('ann@contoso.com')
    expect(d.api.discover).not.toHaveBeenCalled()

    d.api.get.mockResolvedValue(
      view('password', { features: { password_reset: false, federation: true } }),
    )
    d.api.discover.mockRejectedValue(err(429, 'rate_limited', 5))
    await flow.load()
    await flow.discover('ann@contoso.com')
    expect([flow.error.value, flow.retryIn.value, flow.locked.value]).toEqual([null, 0, false])
  })

  it('links at the link step by signing in with a password', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('link'))
    d.api.password.mockResolvedValue(view('mfa'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('ann@example.com', 'pw')
    expect(d.api.password).toHaveBeenCalledWith('tx-1', 'ann@example.com', 'pw')
    expect(flow.view.value?.step).toBe('mfa')
  })

  it('keeps the link step when the account already has an identity at the provider', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('link'))
    d.api.password.mockRejectedValue(err(409, 'already_linked'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('ann@example.com', 'pw')
    expect(d.api.get).toHaveBeenCalledTimes(1)
    expect([flow.view.value?.step, flow.error.value]).toEqual(['link', ALREADY_LINKED])
  })

  it('falls back to the password step when the provider went away', async () => {
    const d = deps()
    d.api.get.mockResolvedValueOnce(view('link')).mockResolvedValueOnce(view('password'))
    d.api.password.mockRejectedValue(err(409, 'link_unavailable'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('ann@example.com', 'pw')
    expect(d.api.get).toHaveBeenCalledTimes(2)
    expect([flow.view.value?.step, flow.error.value, flow.notice.value]).toEqual([
      'password',
      null,
      LINK_UNAVAILABLE,
    ])
  })

  it('says why at the password step when a parked link was dropped', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password', { notice: 'link_unavailable' }))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    expect(flow.notice.value).toBe(LINK_UNAVAILABLE)
  })
})
