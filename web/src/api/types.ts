// Shapes of docs/api/management.md and docs/api/authn.md. Timestamps are RFC 3339 strings.

export interface Paged<T> {
  items: T[]
  next_cursor: string | null
}

export interface Items<T> {
  items: T[]
}

export interface PageQuery {
  limit?: number
  cursor?: string | null
  search?: string
}

export type DirectoryRole = 'GlobalAdmin' | 'ApplicationAdmin' | 'UserAdmin'
export const DIRECTORY_ROLES: DirectoryRole[] = ['GlobalAdmin', 'ApplicationAdmin', 'UserAdmin']
export const ROLE_LABELS: Record<DirectoryRole, string> = {
  GlobalAdmin: 'Global Administrator',
  ApplicationAdmin: 'Application Administrator',
  UserAdmin: 'User Administrator',
}

export interface Tenant {
  id: string
  slug: string
  display_name: string
  is_system: boolean
  disabled: boolean
  audit_retention_days: number
  created_at: string
  updated_at: string
}

export interface User {
  id: string
  email: string
  display_name: string
  user_type: 'member' | 'guest'
  email_verified: boolean
  disabled: boolean
  must_change_password: boolean
  has_password: boolean
  created_at: string
  updated_at: string
}

export interface UserDetail extends User {
  directory_roles: DirectoryRole[]
  mfa: { totp: boolean; totp_pending: boolean; recovery_codes_remaining: number }
}

export interface Session {
  id: string
  amr: string[]
  auth_time: string
  ip: string | null
  user_agent: string | null
  created_at: string
  expires_at: string
  current: boolean
}

export interface Group {
  id: string
  display_name: string
  description: string | null
  created_at: string
  updated_at: string
}

export interface DirectoryRoleAssignment {
  id: string
  user_id: string
  role: DirectoryRole
  created_at: string
}

export type ClientType = 'confidential' | 'public'
export type TokenFormat = 'jwt' | 'opaque'
export type SigningAlg = 'RS256' | 'ES256'

export interface Application {
  id: string
  client_id: string
  display_name: string
  client_type: ClientType
  builtin: boolean
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  identifier_uri: string | null
  audience: string
  access_token_format: TokenFormat
  signing_alg: SigningAlg
  access_token_ttl_secs: number
  refresh_token_ttl_secs: number
  created_at: string
  updated_at: string
}

export interface ApplicationCreate {
  display_name: string
  client_id?: string
  client_type?: ClientType
  redirect_uris?: string[]
}

export type ApplicationPatch = Partial<
  Pick<
    Application,
    | 'display_name'
    | 'redirect_uris'
    | 'post_logout_redirect_uris'
    | 'identifier_uri'
    | 'access_token_format'
    | 'signing_alg'
    | 'access_token_ttl_secs'
    | 'refresh_token_ttl_secs'
  >
>

export interface ClientSecret {
  id: string
  hint: string
  description: string | null
  expires_at: string
  created_at: string
}

export interface Scope {
  id: string
  value: string
  description: string
  admin_consent_required: boolean
  created_at: string
}

export type MemberType = 'user' | 'application'

export interface AppRole {
  id: string
  value: string
  display_name: string
  description: string
  allowed_member_types: MemberType[]
  created_at: string
}

export type PermissionType = 'delegated' | 'application'

export interface RequiredPermission {
  id: string
  resource_application_id: string
  resource_client_id: string
  type: PermissionType
  permission_id: string
  value: string
  created_at: string
}

export type PrincipalType = 'user' | 'group' | 'application'

export interface AppRoleAssignment {
  id: string
  resource_application_id: string
  app_role_id: string
  principal_type: PrincipalType
  principal_id: string
  created_at: string
}

export interface ConsentGrant {
  id: string
  client_application_id: string
  resource_application_id: string
  user_id: string | null
  scopes: string[]
  created_at: string
  updated_at: string
}

export interface AppRef {
  id: string
  client_id: string
  display_name: string
}

export interface MyConsent extends ConsentGrant {
  client: AppRef
  resource: AppRef
}

export interface AuditEvent {
  id: string
  at: string
  actor_type: 'user' | 'application' | 'system'
  actor_id: string | null
  event_type: string
  target_type: string | null
  target_id: string | null
  outcome: 'success' | 'failure'
  ip: string | null
  details: Record<string, unknown>
}

export interface TotpEnrollment {
  secret: string
  otpauth_uri: string
  digits: number
  period: number
  algorithm: string
}

export interface RecoveryCodes {
  recovery_codes: string[]
}
