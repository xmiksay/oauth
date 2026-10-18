import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import type { NotificationPreference, NotificationSettings, Me } from '@/api/types'

const notifications = vi.fn<() => Promise<NotificationSettings>>()
const updateNotifications = vi.fn<(items: NotificationPreference[]) => Promise<NotificationSettings>>()
vi.mock('@/api/me', () => ({ me: { notifications, updateNotifications } }))

const { default: NotificationsPage } = await import('./NotificationsPage.vue')
const { useAuthStore } = await import('@/stores/auth')

const EVENTS = ['password_changed', 'mfa_changed', 'email_changed', 'new_sign_in', 'token_reuse'] as const

function settings(channels = { email: true, telegram: false }): NotificationSettings {
  return { channels, items: EVENTS.map((event) => ({ event, email: true, telegram: true })) }
}

async function mountPage(over: Partial<Me> = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe({
    id: 'u',
    email: 'ann@example.com',
    display_name: 'Ann',
    user_type: 'member',
    email_verified: true,
    disabled: false,
    must_change_password: false,
    has_password: true,
    created_at: '',
    updated_at: '',
    directory_roles: [],
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 0, telegram: false },
    features: { email: true, telegram: false },
    ...over,
  })
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/myaccount', name: 'myaccount', component: NotificationsPage },
      { path: '/myaccount/security', name: 'myaccount-security', component: NotificationsPage },
      { path: '/myaccount/notifications', component: NotificationsPage },
    ],
  })
  await router.push('/myaccount/notifications')
  const w = mount(NotificationsPage, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  notifications.mockReset()
  updateNotifications.mockReset()
})

describe('NotificationsPage', () => {
  it('lists every event and saves the toggles with PUT', async () => {
    notifications.mockResolvedValue(settings())
    updateNotifications.mockImplementation(async (items) => ({ ...settings(), items }))
    const w = await mountPage()
    expect(w.findAll('tbody tr')).toHaveLength(5)
    expect(w.text()).toContain('New sign-in to your account')
    expect(w.find('th:nth-child(3)').exists()).toBe(false) // no Telegram column
    await w.find('[data-testid=email-new_sign_in]').setValue(false)
    await w.find('form').trigger('submit')
    await flushPromises()
    const sent = updateNotifications.mock.calls[0]?.[0]
    expect(sent).toHaveLength(5)
    expect(sent?.find((i) => i.event === 'new_sign_in')).toEqual({
      event: 'new_sign_in',
      email: false,
      telegram: true,
    })
    expect(w.find('[role=status]').text()).toBe('Saved.')
  })

  it('shows the Telegram column only when that channel exists', async () => {
    notifications.mockResolvedValue(settings({ email: true, telegram: true }))
    const w = await mountPage()
    expect(w.find('[data-testid=telegram-token_reuse]').exists()).toBe(true)
    expect(w.findAll('thead th').map((th) => th.text())).toEqual(['Event', 'Email', 'Telegram'])
    expect(w.text()).not.toContain('Link Telegram')
  })

  it('hides the Telegram column until a chat is linked, pointing to Security info', async () => {
    notifications.mockResolvedValue(settings({ email: true, telegram: false }))
    const w = await mountPage({ features: { email: true, telegram: true } })
    expect(w.find('[data-testid=telegram-token_reuse]').exists()).toBe(false)
    expect(w.findAll('thead th').map((th) => th.text())).toEqual(['Event', 'Email'])
    expect(w.find('a[href="/myaccount/security"]').text()).toBe('Link Telegram in Security info')
  })

  it('says nothing about Telegram when the server has no bot', async () => {
    notifications.mockResolvedValue(settings())
    const w = await mountPage()
    expect(w.text()).not.toContain('Telegram')
  })

  it('explains that email is unavailable and disables its toggles', async () => {
    notifications.mockResolvedValue(settings({ email: false, telegram: false }))
    const w = await mountPage()
    expect(w.text()).toContain('Email notifications are unavailable')
    expect(w.find('[data-testid=email-mfa_changed]').attributes('disabled')).toBeDefined()
    expect(w.find('button[type=submit]').attributes('disabled')).toBeDefined()
  })

  it('hints that an unverified address gets no notifications', async () => {
    notifications.mockResolvedValue(settings())
    const w = await mountPage({ email_verified: false })
    expect(w.text()).toContain('sent only to a verified address')
    expect(w.find('a[href="/myaccount"]').exists()).toBe(true)
  })
})
