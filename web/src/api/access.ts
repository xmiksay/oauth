// Role assignments, consents, audit log, tenant settings and tenants.
import { query } from './client'
import { authed, p, t } from './management'
import type {
  AppRoleAssignment,
  AuditEvent,
  ConsentGrant,
  PageQuery,
  Paged,
  PrincipalType,
  Tenant,
} from './types'

export const roleAssignments = {
  list: (
    q: PageQuery & {
      resource_application_id?: string
      app_role_id?: string
      principal_id?: string
    } = {},
  ) => t.get<Paged<AppRoleAssignment>>(`role-assignments${query({ ...q })}`),
  create: (body: { app_role_id: string; principal_type: PrincipalType; principal_id: string }) =>
    t.post<AppRoleAssignment>('role-assignments', body),
  remove: (id: string) => t.del(p`role-assignments/${id}`),
}

export interface ConsentResult {
  grant: ConsentGrant | null
  role_assignments: AppRoleAssignment[]
}

export const consents = {
  list: (
    q: PageQuery & {
      client_application_id?: string
      resource_application_id?: string
      user_id?: string
    } = {},
  ) => t.get<Paged<ConsentGrant>>(`consents${query({ ...q })}`),
  /** "Grant admin consent": without `scopes` / `app_roles` everything required is granted. */
  grant: (body: {
    client_application_id: string
    resource_application_id: string
    scopes?: string[]
    app_roles?: string[]
  }) => t.post<ConsentResult>('consents', body),
  revoke: (id: string) => t.del(p`consents/${id}`),
}

export interface AuditQuery extends PageQuery {
  event_type?: string
  actor_id?: string
  target_id?: string
  from?: string
  to?: string
}

export const auditEvents = {
  list: (q: AuditQuery = {}) => t.get<Paged<AuditEvent>>(`audit-events${query({ ...q })}`),
}

export const settings = {
  get: () => t.get<Tenant>('settings'),
  update: (body: { display_name?: string; audit_retention_days?: number }) =>
    t.patch<Tenant>('settings', body),
}

export interface CreatedTenant {
  tenant: Tenant
  admin: { id: string; email: string }
  one_time_password: string
}

const TENANTS = '/api/v1/tenants'

/** System-tenant endpoints (a system GlobalAdmin's token). */
export const tenants = {
  list: (q: PageQuery = {}) => authed<Paged<Tenant>>(`${TENANTS}${query({ ...q })}`),
  create: (body: {
    slug: string
    display_name: string
    admin_email: string
    admin_display_name?: string
  }) => authed<CreatedTenant>(TENANTS, { method: 'POST', body }),
  update: (
    slug: string,
    body: { display_name?: string; disabled?: boolean; audit_retention_days?: number },
  ) => authed<Tenant>(`${TENANTS}${p`/${slug}`}`, { method: 'PATCH', body }),
}
