// App registrations and their children (`/api/v1/tenants/{t}/applications/…`).
import { query } from './client'
import { p, t } from './management'
import type {
  AppRole,
  Application,
  ApplicationCreate,
  ApplicationPatch,
  ClientSecret,
  Items,
  MemberType,
  PageQuery,
  Paged,
  PermissionType,
  RequiredPermission,
  Scope,
} from './types'

export interface CreatedSecret extends ClientSecret {
  secret: string
}

export const applications = {
  list: (q: PageQuery = {}) => t.get<Paged<Application>>(`applications${query({ ...q })}`),
  get: (id: string) => t.get<Application>(p`applications/${id}`),
  create: (body: ApplicationCreate) => t.post<Application>('applications', body),
  update: (id: string, body: ApplicationPatch) => t.patch<Application>(p`applications/${id}`, body),
  remove: (id: string) => t.del(p`applications/${id}`),
}

export const secrets = {
  list: (app: string) => t.get<Items<ClientSecret>>(p`applications/${app}/secrets`),
  create: (app: string, body: { description?: string; expires_in_days?: number }) =>
    t.post<CreatedSecret>(p`applications/${app}/secrets`, body),
  remove: (app: string, id: string) => t.del(p`applications/${app}/secrets/${id}`),
}

export const scopes = {
  list: (app: string) => t.get<Items<Scope>>(p`applications/${app}/scopes`),
  create: (
    app: string,
    body: { value: string; description?: string; admin_consent_required?: boolean },
  ) => t.post<Scope>(p`applications/${app}/scopes`, body),
  update: (
    app: string,
    id: string,
    body: { description?: string; admin_consent_required?: boolean },
  ) => t.patch<Scope>(p`applications/${app}/scopes/${id}`, body),
  remove: (app: string, id: string) => t.del(p`applications/${app}/scopes/${id}`),
}

export interface AppRoleBody {
  display_name: string
  description?: string
  allowed_member_types: MemberType[]
}

export const appRoles = {
  list: (app: string) => t.get<Items<AppRole>>(p`applications/${app}/roles`),
  create: (app: string, body: AppRoleBody & { value: string }) =>
    t.post<AppRole>(p`applications/${app}/roles`, body),
  update: (app: string, id: string, body: Partial<AppRoleBody>) =>
    t.patch<AppRole>(p`applications/${app}/roles/${id}`, body),
  remove: (app: string, id: string) => t.del(p`applications/${app}/roles/${id}`),
}

export const requiredPermissions = {
  list: (app: string) =>
    t.get<Items<RequiredPermission>>(p`applications/${app}/required-permissions`),
  create: (
    app: string,
    body: { resource_application_id: string; type: PermissionType; value: string },
  ) => t.post<RequiredPermission>(p`applications/${app}/required-permissions`, body),
  remove: (app: string, id: string) => t.del(p`applications/${app}/required-permissions/${id}`),
}
