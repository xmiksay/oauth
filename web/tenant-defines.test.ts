import { describe, expect, it } from 'vitest'
import { DEFAULT_TENANT_DEFINES, tenantDefines } from './tenant-defines.ts'

const env =
  (vars: Record<string, string>) =>
  (key: string): string | undefined =>
    vars[key]

describe('tenantDefines', () => {
  it('ignores the .env outside the dev server, even a malformed one', () => {
    const read = env({ SYSTEM_TENANT_SLUG: 'Bad Slug', APEX_TENANT: 'prod' })
    expect(tenantDefines(false, read)).toEqual({
      __SYSTEM_TENANT_SLUG__: '"system"',
      __APEX_TENANT__: '""',
    })
    expect(DEFAULT_TENANT_DEFINES).toEqual(tenantDefines(false, read))
  })

  it("takes the dev server's slugs from the .env, trimmed", () => {
    expect(tenantDefines(true, env({ SYSTEM_TENANT_SLUG: ' config ', APEX_TENANT: 'prod' }))).toEqual(
      { __SYSTEM_TENANT_SLUG__: '"config"', __APEX_TENANT__: '"prod"' },
    )
  })

  it('defaults the dev server to `system` and no apex tenant', () => {
    expect(tenantDefines(true, env({ APEX_TENANT: '  ' }))).toEqual(DEFAULT_TENANT_DEFINES)
  })

  it('refuses a malformed slug on the dev server', () => {
    expect(() => tenantDefines(true, env({ APEX_TENANT: 'Prod' }))).toThrow(/APEX_TENANT/)
    expect(() => tenantDefines(true, env({ SYSTEM_TENANT_SLUG: 'a' }))).toThrow(/SYSTEM_TENANT_SLUG/)
  })

  it('refuses an APEX_TENANT naming the system tenant', () => {
    expect(() => tenantDefines(true, env({ APEX_TENANT: 'system' }))).toThrow(/system tenant/)
  })
})
