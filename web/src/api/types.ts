// Shapes of docs/api/management.md and docs/api/authn.md. Timestamps are RFC 3339 strings.
import type { PasskeyAssertion } from './webauthnTypes'

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
  /** `passkeys`: how many passkeys the user has registered. */
  mfa: {
    totp: boolean
    totp_pending: boolean
    recovery_codes_remaining: number
    passkeys: number
    /** A Telegram chat is linked (sign-in codes and notifications can go there). */
    telegram: boolean
  }
}

/** An upstream identity linked to a user (`GET users/{id}` → `identities`). */
export interface UserIdentity {
  id: string
  idp_id: string
  idp_name: string
  /** The upstream `sub`. */
  subject: string
  email: string | null
  linked_at: string
  last_used_at: string | null
}

/** `GET users/{id}`: the admin view, with linked upstream identities. */
export interface AdminUserDetail extends UserDetail {
  identities: UserIdentity[]
}

/** `GET` / `PATCH me`: the caller's own `UserDetail` plus what the server offers. */
export type Me = UserDetail & {
  /**
   * `email`: the server can send email (verification, invitations, notifications);
   * `telegram`: a Telegram bot is configured (sign-in codes, notifications).
   */
  features: { email: boolean; telegram: boolean }
}

/** `GET me/telegram`; `username` (no `@`) may be null even when linked. */
export interface TelegramStatus {
  linked: boolean
  username: string | null
  linked_at: string | null
}

/**
 * `POST me/telegram/link`: the bot deep link carries a single-use bearer code — hold it only
 * in the showing component's state, never in a store, storage or logs.
 */
export interface TelegramLink {
  url: string
  expires_at: string
}

export type NotificationEvent =
  | 'password_changed'
  | 'mfa_changed'
  | 'email_changed'
  | 'new_sign_in'
  | 'token_reuse'
  | 'identity_linked'

export interface NotificationPreference {
  event: NotificationEvent
  email: boolean
  telegram: boolean
}

export interface NotificationSettings {
  /** Channels this server can deliver on. */
  channels: { email: boolean; telegram: boolean }
  items: NotificationPreference[]
}

/** An identity provider as the login page and My Account list it. */
export interface IdpRef {
  id: string
  name: string
}

/** `GET me/identities`: `available` = enabled providers the user hasn't linked yet. */
export interface MyIdentities {
  items: Omit<UserIdentity, 'subject'>[]
  available: IdpRef[]
}

export type MyIdentity = MyIdentities['items'][number]

export type IdpPolicy = 'jit' | 'link_only' | 'deny'
export type IdpClientAuth = 'post' | 'basic'

/** An upstream OIDC provider; the client secret is write-only (`has_secret` only). */
export interface IdentityProvider {
  id: string
  name: string
  kind: 'oidc'
  enabled: boolean
  visible: boolean
  issuer: string
  discovery_url: string | null
  client_id: string
  has_secret: boolean
  client_auth: IdpClientAuth
  scopes: string[]
  policy: IdpPolicy
  trust_upstream_mfa: boolean
  mfa_acr: string | null
  email_domains: string[]
  /** Register this at the provider. */
  redirect_uri: string
  created_at: string
  updated_at: string
}

/** `GET` / `PATCH identity-providers/{id}`. */
export interface IdentityProviderDetail extends IdentityProvider {
  /** Users with no other way to sign in (no password, passkey or other provider). */
  users_only_via: number
  /** Identities linked through this provider; changing `issuer` / `client_id` unlinks them all. */
  linked_users: number
}

/**
 * `POST` body; as a `PATCH` body every field is optional. `client_secret`: a string replaces
 * the secret, `null` removes it, omitted keeps it.
 */
export interface IdentityProviderInput {
  name: string
  issuer: string
  client_id: string
  client_secret?: string | null
  client_auth?: IdpClientAuth
  discovery_url?: string | null
  scopes?: string[]
  policy?: IdpPolicy
  trust_upstream_mfa?: boolean
  mfa_acr?: string | null
  email_domains?: string[]
  enabled?: boolean
  visible?: boolean
}

export type IdentityProviderPatch = Partial<IdentityProviderInput>

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

export interface Passkey {
  id: string
  name: string
  created_at: string
  last_used_at: string | null
  backup_eligible: boolean
  /** Synced to a cloud keychain (else bound to one device). */
  backup_state: boolean
  transports: string[]
  aaguid: string
}

export type * from './webauthnTypes'

/** Re-authentication for sensitive `me/…` calls: exactly one of the two. */
export type Reauth = { password: string } | { passkey: PasskeyAssertion }
