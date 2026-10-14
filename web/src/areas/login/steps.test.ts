import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import PasswordStep from './PasswordStep.vue'
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

  it('labels its inputs for assistive tech and password managers', () => {
    const w = mount(PasswordStep, { props: { locked: false } })
    expect(w.find('label[for=login-email]').exists()).toBe(true)
    expect(w.find('#login-password').attributes('autocomplete')).toBe('current-password')
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
