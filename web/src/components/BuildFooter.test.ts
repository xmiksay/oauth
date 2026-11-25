import { afterEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import BuildFooter from './BuildFooter.vue'

function setMeta(content: string) {
  const tag = document.createElement('meta')
  tag.name = 'oauth-build'
  tag.content = content
  document.head.appendChild(tag)
}

afterEach(() => {
  document.head.querySelectorAll('meta[name="oauth-build"]').forEach((m) => m.remove())
})

describe('BuildFooter', () => {
  it('shows the version and commit the server wrote into the page', () => {
    setMeta('0.4.2+0123456789ab')
    const w = mount(BuildFooter)
    expect(w.find('footer').text()).toBe('v0.4.2 · 0123456789ab')
  })

  it('renders nothing without the meta (Vite dev server)', () => {
    const w = mount(BuildFooter)
    expect(w.find('footer').exists()).toBe(false)
  })
})
