import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { fakeMe } from '@/test/helpers'
import UserBadges from './UserBadges.vue'

describe('UserBadges', () => {
  it('marks a user managed by oauth apply', () => {
    expect(mount(UserBadges, { props: { user: fakeMe() } }).text()).not.toContain(
      'Managed by apply',
    )
    expect(mount(UserBadges, { props: { user: fakeMe({ managed: true }) } }).text()).toContain(
      'Managed by apply',
    )
  })
})
