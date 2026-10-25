import { describe, expect, it } from 'vitest'
import adminLayout from '@/areas/admin/AdminLayout.vue?raw'
import appHeader from './AppHeader.vue?raw'

// jsdom computes no stacking, so pin the z-index order across the two files instead.
function zOf(source: string, marker: string): number {
  const tag = source.split('<').find((t) => t.includes(marker))
  const z = tag?.match(/\bz-(\d+)\b/)
  if (!z?.[1]) throw new Error(`no z-* class on the tag containing ${marker}`)
  return Number(z[1])
}

describe('AppHeader layering', () => {
  it('keeps the header (and the menus inside it) above the admin side nav and its backdrop', () => {
    const header = zOf(appHeader, 'class="sticky')
    const nav = zOf(adminLayout, 'id="side-nav"')
    const backdrop = zOf(adminLayout, '@click="menuOpen = false"')
    expect(header).toBeGreaterThan(nav)
    expect(nav).toBeGreaterThan(backdrop)
  })
})
