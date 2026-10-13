import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import SecretOnceDialog from './SecretOnceDialog.vue'

afterEach(() => vi.unstubAllGlobals())

describe('SecretOnceDialog', () => {
  it('renders nothing while closed', () => {
    const w = mount(SecretOnceDialog, { props: { title: 'Secret', values: null } })
    expect(w.find('[data-testid=secret-values]').exists()).toBe(false)
  })

  it('shows the values with a you-won’t-see-it-again warning', async () => {
    const w = mount(SecretOnceDialog, { props: { title: 'Secret', values: ['s3cr3t'] } })
    await flushPromises()
    expect(w.find('[data-testid=secret-values]').text()).toBe('s3cr3t')
    expect(w.find('[role=alert]').text()).toMatch(/won't be able to see it again/)
    expect(w.find('dialog').attributes('open')).toBeDefined()
  })

  it('copies all values to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const w = mount(SecretOnceDialog, { props: { title: 'Codes', values: ['a', 'b'] } })
    await w.findAll('button').find((b) => b.text() === 'Copy')?.trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith('a\nb')
    expect(w.text()).toContain('Copied')
  })

  it('offers a download only with a filename', () => {
    const plain = mount(SecretOnceDialog, { props: { title: 'S', values: ['a'] } })
    expect(plain.findAll('button').some((b) => b.text() === 'Download')).toBe(false)
    const codes = mount(SecretOnceDialog, {
      props: { title: 'S', values: ['a'], filename: 'codes.txt' },
    })
    expect(codes.findAll('button').some((b) => b.text() === 'Download')).toBe(true)
  })

  it('asks the parent to drop the values on Done', async () => {
    const w = mount(SecretOnceDialog, { props: { title: 'S', values: ['a'] } })
    await w.findAll('button').find((b) => b.text() === 'Done')?.trigger('click')
    expect(w.emitted('close')).toHaveLength(1)
  })
})
