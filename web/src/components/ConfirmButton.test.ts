import { describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ConfirmButton from './ConfirmButton.vue'
import { ApiError } from '@/api/client'

function button(w: ReturnType<typeof mount>, name: string) {
  const b = w.findAll('button').find((x) => x.text() === name)
  if (!b) throw new Error(`no button ${name}`)
  return b
}

describe('ConfirmButton', () => {
  it('runs the action only after confirmation and emits done', async () => {
    let calls = 0
    const w = mount(ConfirmButton, {
      props: { label: 'Delete', title: 'Delete?', message: 'Sure?', action: async () => calls++ },
    })
    await button(w, 'Delete').trigger('click')
    expect(calls).toBe(0)
    await w.findAll('button').at(-1)?.trigger('click')
    await flushPromises()
    expect(calls).toBe(1)
    expect(w.emitted('done')).toHaveLength(1)
  })

  it('shows the error, keeps the dialog open, and clears the error on reopen', async () => {
    const w = mount(ConfirmButton, {
      props: {
        label: 'Remove',
        title: 'Remove?',
        message: 'Sure?',
        action: async () => {
          throw new ApiError(409, { error: 'conflict', error_description: 'last admin' })
        },
      },
    })
    await button(w, 'Remove').trigger('click')
    await w.findAll('button').at(-1)?.trigger('click')
    await flushPromises()
    expect(w.find('[role=alert]').text()).toBe('last admin')
    await button(w, 'Cancel').trigger('click')
    await button(w, 'Remove').trigger('click')
    expect(w.find('[role=alert]').exists()).toBe(false)
  })

  it('disables Cancel and confirm while the action runs', async () => {
    let finish: () => void = () => {}
    const w = mount(ConfirmButton, {
      props: {
        label: 'Go',
        title: 'Go?',
        message: 'Sure?',
        action: () => new Promise<void>((r) => (finish = r)),
      },
    })
    await button(w, 'Go').trigger('click')
    await w.findAll('button').at(-1)?.trigger('click')
    expect(button(w, 'Cancel').attributes('disabled')).toBeDefined()
    expect(w.findAll('button').at(-1)?.attributes('disabled')).toBeDefined()
    finish()
    await flushPromises()
    expect(w.emitted('done')).toHaveLength(1)
  })
})
