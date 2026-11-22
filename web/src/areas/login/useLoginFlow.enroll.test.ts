import { describe, expect, it } from 'vitest'
import { useLoginFlow } from './useLoginFlow'
import { deps, err, view } from './flowFixtures'

const ENROLLMENT = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauth_uri: 'otpauth://totp/x',
  digits: 6,
  period: 30,
  algorithm: 'SHA1',
}

async function started() {
  const d = deps()
  d.api.get.mockResolvedValue(view('mfa_enroll'))
  const flow = useLoginFlow('tx-1', d.deps)
  await flow.load()
  return { d, flow }
}

describe('useLoginFlow enrolment', () => {
  it('hands the pending secret to the caller without keeping it', async () => {
    const { d, flow } = await started()
    d.api.enrollTotp.mockResolvedValue(ENROLLMENT)
    expect(await flow.beginTotp()).toEqual(ENROLLMENT)
    expect(d.api.enrollTotp).toHaveBeenCalledWith('tx-1')
    expect(flow.view.value?.step).toBe('mfa_enroll')
  })

  it('returns the recovery codes and continues only on resume', async () => {
    const { d, flow } = await started()
    d.api.confirmEnrollTotp.mockResolvedValue({ recovery_codes: ['aaaa-bbbb-cccc'] })
    expect(await flow.confirmTotp(' 123 456 ')).toEqual(['aaaa-bbbb-cccc'])
    expect(d.api.confirmEnrollTotp).toHaveBeenCalledWith('tx-1', '123456')
    expect(d.api.enrollContinue).not.toHaveBeenCalled()
    expect(d.navigate).not.toHaveBeenCalled()
    d.api.enrollContinue.mockResolvedValue({ redirect: 'https://shop/cb?code=c' })
    await flow.resume()
    expect(d.api.enrollContinue).toHaveBeenCalledWith('tx-1')
    expect(d.navigate).toHaveBeenCalledWith('https://shop/cb?code=c')
  })

  it('reports a wrong code and returns nothing', async () => {
    const { d, flow } = await started()
    d.api.confirmEnrollTotp.mockRejectedValue(err(401, 'invalid_code'))
    expect(await flow.confirmTotp('000000')).toBeNull()
    expect(flow.error.value).toBe("That code didn't work. Check it and try again.")
    expect(d.api.enrollContinue).not.toHaveBeenCalled()
  })

  it('registers a passkey with fresh creation options', async () => {
    const { d, flow } = await started()
    const options = { publicKey: { challenge: 'c' } }
    const credential = { id: 'cred' }
    d.api.enrollPasskeyOptions.mockResolvedValue(options)
    d.passkeys.create.mockResolvedValue(credential)
    d.api.enrollPasskey.mockResolvedValue(view('consent'))
    await flow.enrollPasskey()
    expect(d.passkeys.create).toHaveBeenCalledWith(options)
    expect(d.api.enrollPasskey).toHaveBeenCalledWith('tx-1', credential)
    expect(flow.view.value?.step).toBe('consent')
  })
})
