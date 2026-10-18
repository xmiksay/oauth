import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import type { TelegramStatus } from '@/api/types'
import { fakeMe } from '@/test/helpers'

const api = {
  getTelegram: vi.fn(),
  linkTelegram: vi.fn(),
  unlinkTelegram: vi.fn(),
  reauthOptions: vi.fn(),
}
vi.mock('@/api/me', () => ({ me: api }))

const { default: TelegramSection } = await import('./TelegramSection.vue')
const { useAuthStore } = await import('@/stores/auth')

const NOW = new Date('2026-10-14T10:00:00Z')
const URL = 'https://t.me/oauth_bot?start=secret-code'
const unlinked: TelegramStatus = { linked: false, username: null, linked_at: null }
const linked: TelegramStatus = {
  linked: true,
  username: 'ann_t',
  linked_at: '2026-10-14T10:00:05Z',
}

async function mountSection() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useAuthStore().setMe(fakeMe({ features: { email: true, telegram: true } }))
  const w = mount(TelegramSection, { global: { plugins: [pinia] }, attachTo: document.body })
  await flushPromises()
  return w
}

async function click(w: ReturnType<typeof mount>, text: string) {
  await w
    .findAll('button')
    .find((b) => b.text() === text)
    ?.trigger('click')
  await flushPromises()
}

async function confirmPassword(w: ReturnType<typeof mount>) {
  await w.find('#pp-password').setValue('pw')
  await w.find('#reauth-prompt').trigger('submit')
  await flushPromises()
}

/** Re-auth → POST link, leaving the section polling. */
async function startLink(w: ReturnType<typeof mount>, expiresInSecs = 600) {
  const expires_at = new Date(NOW.getTime() + expiresInSecs * 1000).toISOString()
  api.linkTelegram.mockResolvedValue({ url: URL, expires_at })
  await click(w, 'Link Telegram')
  await confirmPassword(w)
}

const tick = async () => {
  await vi.advanceTimersByTimeAsync(3000)
  await flushPromises()
}

let open: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
  vi.setSystemTime(NOW)
  Object.values(api).forEach((f) => f.mockReset())
  api.getTelegram.mockResolvedValue(unlinked)
  open = vi.fn()
  vi.stubGlobal('open', open)
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('TelegramSection', () => {
  it('links: re-auth, opens the deep link, polls until linked', async () => {
    const w = await mountSection()
    expect(w.text()).toContain('Not linked.')
    expect(w.text()).toContain('sign-in may also ask for a code sent to you via Telegram')
    await startLink(w)
    expect(api.linkTelegram).toHaveBeenCalledWith({ password: 'pw' })
    expect(open).toHaveBeenCalledWith(URL, '_blank', 'noopener,noreferrer')
    const pending = w.find('[data-testid=telegram-pending]')
    expect(pending.text()).toContain('Open Telegram and press Start')
    const a = pending.find('a')
    expect(a.attributes('href')).toBe(URL)
    expect(a.attributes('rel')).toBe('noopener noreferrer')

    api.getTelegram.mockClear()
    api.getTelegram.mockResolvedValueOnce(unlinked).mockResolvedValueOnce(linked)
    await tick()
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
    expect(w.find('[data-testid=telegram-pending]').exists()).toBe(true)
    await tick()
    expect(api.getTelegram).toHaveBeenCalledTimes(2)
    expect(w.find('[data-testid=telegram-pending]').exists()).toBe(false)
    expect(w.text()).toContain('Linked to @ann_t since')
    expect(w.find('[role=status]').text()).toBe('Telegram linked.')
    expect(w.text()).not.toContain(URL)
    expect(w.emitted('changed')).toHaveLength(1)
    await tick()
    expect(api.getTelegram).toHaveBeenCalledTimes(2) // polling stopped
  })

  it('stops polling when the link expires', async () => {
    const w = await mountSection()
    await startLink(w, 5)
    api.getTelegram.mockClear()
    await tick() // 3 s: still valid, polls
    await tick() // 6 s: expired, no request
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
    expect(w.find('[data-testid=telegram-pending]').exists()).toBe(false)
    expect(w.find('[role=alert]').text()).toBe('The link expired — try again.')
    await tick()
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
  })

  it('stops polling on cancel and on unmount', async () => {
    const w = await mountSection()
    await startLink(w)
    api.getTelegram.mockClear()
    await click(w, 'Cancel')
    expect(w.find('[data-testid=telegram-pending]').exists()).toBe(false)
    await tick()
    expect(api.getTelegram).not.toHaveBeenCalled()

    await startLink(w)
    w.unmount()
    await tick()
    expect(api.getTelegram).not.toHaveBeenCalled()
  })

  it('never re-arms when unmounted while a poll is in flight', async () => {
    const w = await mountSection()
    await startLink(w)
    api.getTelegram.mockClear()
    let answer: (s: typeof unlinked) => void = () => {}
    api.getTelegram.mockReturnValueOnce(new Promise((resolve) => (answer = resolve)))
    await vi.advanceTimersByTimeAsync(3000)
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
    w.unmount()
    answer(unlinked)
    await flushPromises()
    await tick()
    await tick()
    expect(api.getTelegram).toHaveBeenCalledTimes(1)
  })

  it('shows a wrong password in the prompt and starts nothing', async () => {
    const w = await mountSection()
    api.linkTelegram.mockRejectedValue(new ApiError(403, { error: 'forbidden' }))
    await click(w, 'Link Telegram')
    await confirmPassword(w)
    expect(w.text()).toContain('Your current password is incorrect.')
    expect(open).not.toHaveBeenCalled()
  })

  it('unlinks after re-auth', async () => {
    api.getTelegram.mockResolvedValue({ ...linked, username: null })
    api.unlinkTelegram.mockResolvedValue(undefined)
    const w = await mountSection()
    expect(w.text()).toContain('Linked since')
    await click(w, 'Unlink')
    await confirmPassword(w)
    expect(api.unlinkTelegram).toHaveBeenCalledWith({ password: 'pw' })
    expect(w.text()).toContain('Not linked.')
    expect(w.find('[role=status]').text()).toBe('Telegram unlinked.')
    expect(w.emitted('changed')).toHaveLength(1)
  })
})
