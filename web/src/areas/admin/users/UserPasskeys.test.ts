import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ApiError } from '@/api/client'
import { fakePasskey } from '@/test/helpers'

const users = { passkeys: vi.fn(), removePasskey: vi.fn() }
vi.mock('@/api/directory', () => ({ users }))

const { default: UserPasskeys } = await import('./UserPasskeys.vue')

async function mountCard(canWrite = true) {
  const w = mount(UserPasskeys, { props: { userId: 'u1', canWrite }, attachTo: document.body })
  await flushPromises()
  return w
}

const button = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').filter((b) => b.text() === text)

beforeEach(() => {
  users.passkeys.mockReset().mockResolvedValue({ items: [fakePasskey()] })
  users.removePasskey.mockReset()
  document.body.innerHTML = ''
})

describe('UserPasskeys', () => {
  it('lists the passkeys read-only without write access', async () => {
    const w = await mountCard(false)
    expect(users.passkeys).toHaveBeenCalledWith('u1')
    expect(w.find('tbody').text()).toContain('Laptop')
    expect(button(w, 'Remove')).toHaveLength(0)
  })

  it('removes a passkey after confirmation and reports the change', async () => {
    users.removePasskey.mockResolvedValue(undefined)
    const w = await mountCard()
    users.passkeys.mockResolvedValue({ items: [] })
    await button(w, 'Remove')[0]?.trigger('click')
    await button(w, 'Remove')[1]?.trigger('click')
    await flushPromises()
    expect(users.removePasskey).toHaveBeenCalledWith('u1', 'pk1')
    expect(w.text()).toContain('No passkeys.')
    expect(w.emitted('changed')).toHaveLength(1)
  })

  it("explains why the last sign-in method can't be removed", async () => {
    users.removePasskey.mockRejectedValue(new ApiError(409, { error: 'conflict' }))
    const w = await mountCard()
    await button(w, 'Remove')[0]?.trigger('click')
    await button(w, 'Remove')[1]?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toMatch(/Set a password first/)
    expect(w.emitted('changed')).toBeUndefined()
  })
})
