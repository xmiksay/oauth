import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import PasswordStep from './PasswordStep.vue'
import MfaStep from './MfaStep.vue'
import ChangePasswordStep from './ChangePasswordStep.vue'
import ConsentStep from './ConsentStep.vue'
import type { TxView } from '@/api/authn'

describe('PasswordStep', () => {
  it('submits the trimmed email and the password as typed', async () => {
    const w = mount(PasswordStep, { props: { locked: false } })
    await w.find('#login-email').setValue('  ann@example.com ')
    await w.find('#login-password').setValue(' secret ')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([['ann@example.com', ' secret ']])
  })

  it('disables the button while locked (busy or rate limited)', () => {
    const w = mount(PasswordStep, { props: { locked: true } })
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()
  })

  it('offers a passkey only when asked to, and emits it', async () => {
    const plain = mount(PasswordStep, { props: { locked: false } })
    expect(plain.findAll('button').map((b) => b.text())).toEqual(['Sign in'])
    const w = mount(PasswordStep, { props: { locked: false, passkey: true } })
    expect(w.find('#login-email').attributes('autocomplete')).toBe('username webauthn')
    await w.findAll('button').find((b) => b.text() === 'Sign in with a passkey')?.trigger('click')
    expect(w.emitted('passkey')).toHaveLength(1)
    expect(w.emitted('submit')).toBeUndefined()
  })

  it('labels its inputs for assistive tech and password managers', () => {
    const w = mount(PasswordStep, { props: { locked: false } })
    expect(w.find('label[for=login-email]').exists()).toBe(true)
    expect(w.find('#login-password').attributes('autocomplete')).toBe('current-password')
  })
})

describe('MfaStep', () => {
  const buttons = (w: ReturnType<typeof mount>) => w.findAll('button').map((b) => b.text())

  it('toggles between code kinds only when the user has both', async () => {
    const both = mount(MfaStep, {
      props: { locked: false, factors: ['totp', 'recovery'], passkeys: true },
    })
    expect(buttons(both)).toEqual(['Verify', 'Use a recovery code instead'])
    const totpOnly = mount(MfaStep, { props: { locked: false, factors: ['totp'], passkeys: true } })
    expect(buttons(totpOnly)).toEqual(['Verify'])
  })

  it('offers a passkey next to the code and emits it', async () => {
    const w = mount(MfaStep, {
      props: { locked: false, factors: ['totp', 'passkey'], passkeys: true },
    })
    expect(w.find('#mfa-code').exists()).toBe(true)
    await w.findAll('button').find((b) => b.text() === 'Use a passkey')?.trigger('click')
    expect(w.emitted('passkey')).toHaveLength(1)
  })

  it('offers no Telegram without the factor', () => {
    const w = mount(MfaStep, { props: { locked: false, factors: ['totp'], passkeys: true } })
    expect(w.text()).not.toContain('Telegram')
  })

  it('starts with Telegram without an app: send, then type and submit the code', async () => {
    const w = mount(MfaStep, {
      props: { locked: false, factors: ['telegram', 'recovery'], passkeys: true },
    })
    expect(buttons(w)).toEqual(['Send code via Telegram', 'Use a recovery code instead'])
    expect(w.find('#telegram-code').exists()).toBe(false)
    await w.findAll('button').find((b) => b.text() === 'Send code via Telegram')?.trigger('click')
    expect(w.emitted('telegramSend')).toHaveLength(1)

    await w.setProps({ telegramSent: true })
    const input = w.find('#telegram-code')
    expect(input.attributes('autocomplete')).toBe('one-time-code')
    expect(input.attributes('inputmode')).toBe('numeric')
    await input.setValue('123 456')
    await w.find('form').trigger('submit')
    expect(w.emitted('telegram')).toEqual([['123 456']])
    expect(w.emitted('totp')).toBeUndefined()

    await w.findAll('button').find((b) => b.text() === 'Send a new code')?.trigger('click')
    expect(w.emitted('telegramSend')).toHaveLength(2)
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('switches from the app to Telegram and disables sending while locked', async () => {
    const w = mount(MfaStep, {
      props: { locked: true, factors: ['totp', 'telegram'], passkeys: true },
    })
    expect(buttons(w)).toEqual(['Verify', 'Get a code via Telegram instead'])
    await w.findAll('button').find((b) => b.text() === 'Get a code via Telegram instead')?.trigger('click')
    const send = w.findAll('button').find((b) => b.text() === 'Send code via Telegram')
    expect(send?.attributes('disabled')).toBeDefined()
    expect(buttons(w)).toContain('Use my authenticator app instead')
  })

  it('explains a passkey-only user on a browser without passkeys', () => {
    const w = mount(MfaStep, { props: { locked: false, factors: ['passkey'], passkeys: false } })
    expect(w.findAll('button')).toHaveLength(0)
    expect(w.find('[role=alert]').text()).toMatch(/can't use passkeys/)
  })
})

describe('ChangePasswordStep', () => {
  it('checks length and confirmation before submitting', async () => {
    const w = mount(ChangePasswordStep, { props: { locked: false } })
    await w.find('#new-password').setValue('short')
    await w.find('#confirm-password').setValue('short')
    await w.find('form').trigger('submit')
    expect(w.find('[role=alert]').text()).toMatch(/at least 12/)
    await w.find('#new-password').setValue('long-enough-password')
    await w.find('#confirm-password').setValue('long-enough-passw0rd')
    await w.find('form').trigger('submit')
    expect(w.find('[role=alert]').text()).toMatch(/do not match/)
    expect(w.emitted('submit')).toBeUndefined()
    await w.find('#confirm-password').setValue('long-enough-password')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([['long-enough-password']])
  })
})

describe('ConsentStep', () => {
  const view: TxView = {
    tx: 't',
    step: 'consent',
    factors: [],
    tenant: { slug: 'c', display_name: 'Contoso' },
    client: { client_id: 'shop', display_name: 'Shop' },
    user: { email: 'ann@example.com', display_name: 'Ann' },
    consent: {
      resource: { display_name: 'Orders API', audience: 'api://orders' },
      scopes: [
        { value: 'Orders.Read', description: 'Read your orders' },
        { value: 'Orders.Write', description: '' },
      ],
    },
    features: { password_reset: false },
  }

  it('names the client, the resource and every requested scope', () => {
    const w = mount(ConsentStep, { props: { view, locked: false } })
    expect(w.text()).toContain('Shop wants to access')
    expect(w.text()).toContain('Orders API')
    const items = w.findAll('li').map((li) => li.text())
    expect(items[0]).toContain('Read your orders')
    expect(items[1]).toContain('Orders.Write') // falls back to the value without a description
  })

  it('emits the decision', async () => {
    const w = mount(ConsentStep, { props: { view, locked: false } })
    const [cancel, accept] = w.findAll('button')
    await accept?.trigger('click')
    await cancel?.trigger('click')
    expect(w.emitted('decide')).toEqual([[true], [false]])
  })
})
