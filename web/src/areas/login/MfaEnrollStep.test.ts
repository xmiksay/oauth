import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import MfaEnrollStep from './MfaEnrollStep.vue'

const ENROLLMENT = {
  secret: 'JBSWY3DPEHPK3PXP',
  otpauth_uri: 'otpauth://totp/x',
  digits: 6,
  period: 30,
  algorithm: 'SHA1',
}

function mountStep(passkeys = true, enrolled = false) {
  const begin = vi.fn(async () => ENROLLMENT)
  const confirm = vi.fn(async () => ['aaaa-bbbb-cccc'])
  const w = mount(MfaEnrollStep, {
    props: { locked: false, enrolled, passkeys, begin, confirm },
    global: { stubs: { QrCode: true, SecretOnceDialog: true } },
  })
  return { w, begin, confirm }
}

describe('MfaEnrollStep', () => {
  it('offers a passkey only where the browser can create one', async () => {
    const { w } = mountStep()
    const passkey = w.findAll('button').find((b) => b.text() === 'Create a passkey')
    await passkey?.trigger('click')
    expect(w.emitted('passkey')).toHaveLength(1)
    const plain = mountStep(false).w
    expect(plain.findAll('button').map((b) => b.text())).toEqual(['Use an authenticator app'])
  })

  it('shows the secret, confirms the code, then the recovery codes before continuing', async () => {
    const { w, begin, confirm } = mountStep()
    await w.find('button').trigger('click')
    await flushPromises()
    expect(begin).toHaveBeenCalled()
    expect(w.text()).toContain(ENROLLMENT.secret)
    await w.find('#enroll-code').setValue('123456')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(confirm).toHaveBeenCalledWith('123456')
    const dialog = w.findComponent({ name: 'SecretOnceDialog' })
    expect(dialog.props('values')).toEqual(['aaaa-bbbb-cccc'])
    expect(w.text()).not.toContain(ENROLLMENT.secret)
    expect(w.emitted('done')).toBeUndefined()
    dialog.vm.$emit('close')
    await flushPromises()
    expect(w.emitted('done')).toHaveLength(1)
  })

  it('only continues once a factor is already set up', async () => {
    const { w, begin } = mountStep(true, true)
    expect(w.findAll('button').map((b) => b.text())).toEqual(['Continue'])
    await w.find('button').trigger('click')
    expect(w.emitted('done')).toHaveLength(1)
    expect(begin).not.toHaveBeenCalled()
  })
})
