import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ResetPasswordButton from './ResetPasswordButton.vue'

const buttons = (w: ReturnType<typeof mount>, text: string) =>
  w.findAll('button').filter((b) => b.text() === text)

async function confirmReset(oneTime: string | null) {
  const action = vi.fn().mockResolvedValue({ one_time_password: oneTime, must_change_password: true })
  const w = mount(ResetPasswordButton, { props: { action }, attachTo: document.body })
  await buttons(w, 'Reset password')[0]?.trigger('click')
  await buttons(w, 'Reset password')[1]?.trigger('click')
  await flushPromises()
  expect(action).toHaveBeenCalledOnce()
  return w
}

describe('ResetPasswordButton', () => {
  it('shows the temporary password once, emits reset and clears it on close', async () => {
    const w = await confirmReset('Temp-123')
    expect(w.emitted('reset')).toHaveLength(1)
    expect(w.find('[data-testid=secret-values]').text()).toBe('Temp-123')
    await buttons(w, 'Done')[0]?.trigger('click')
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
    expect(w.html()).not.toContain('Temp-123')
    w.unmount()
  })

  it('opens no dialog when the server returns no password', async () => {
    const w = await confirmReset(null)
    expect(w.emitted('reset')).toHaveLength(1)
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
    w.unmount()
  })
})
