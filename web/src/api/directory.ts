// Users, groups and directory roles (`/api/v1/…` on the tenant's host).
import { query } from './client'
import { p, t } from './management'
import type {
  DirectoryRole,
  DirectoryRoleAssignment,
  Group,
  Items,
  PageQuery,
  Paged,
  Passkey,
  Session,
  User,
  UserDetail,
} from './types'

export interface CreatedUser {
  user: User
  one_time_password: string | null
  invite_sent: boolean
}

/** `invite: true` excludes `password` / `must_change_password` (the user sets it via the link). */
export type UserCreate = {
  email: string
  display_name: string
} & (
  | { invite: true }
  | { invite?: false; password?: string; must_change_password?: boolean }
)

export interface PasswordReset {
  one_time_password: string | null
  must_change_password: boolean
}

export const users = {
  list: (q: PageQuery = {}) => t.get<Paged<User>>(`users${query({ ...q })}`),
  get: (id: string) => t.get<UserDetail>(p`users/${id}`),
  create: (body: UserCreate) => t.post<CreatedUser>('users', body),
  update: (id: string, body: { display_name?: string; email?: string; disabled?: boolean }) =>
    t.patch<User>(p`users/${id}`, body),
  remove: (id: string) => t.del(p`users/${id}`),
  resetPassword: (id: string, body: { password?: string; must_change_password?: boolean } = {}) =>
    t.post<PasswordReset>(p`users/${id}/reset-password`, body),
  resetMfa: (id: string) => t.post<void>(p`users/${id}/reset-mfa`),
  /** Re-sends the invitation; the previous link stops working. */
  resendInvite: (id: string) => t.post<void>(p`users/${id}/invite`),
  sessions: (id: string) => t.get<Items<Session>>(p`users/${id}/sessions`),
  passkeys: (id: string) => t.get<Items<Passkey>>(p`users/${id}/passkeys`),
  removePasskey: (id: string, passkeyId: string) => t.del(p`users/${id}/passkeys/${passkeyId}`),
  revokeSessions: (id: string) => t.post<void>(p`users/${id}/revoke-sessions`),
}

export const groups = {
  list: (q: PageQuery = {}) => t.get<Paged<Group>>(`groups${query({ ...q })}`),
  get: (id: string) => t.get<Group>(p`groups/${id}`),
  create: (body: { display_name: string; description?: string }) => t.post<Group>('groups', body),
  update: (id: string, body: { display_name?: string; description?: string }) =>
    t.patch<Group>(p`groups/${id}`, body),
  remove: (id: string) => t.del(p`groups/${id}`),
  members: (id: string, q: PageQuery = {}) =>
    t.get<Paged<User>>(`${p`groups/${id}/members`}${query({ ...q })}`),
  addMember: (id: string, userId: string) =>
    t.post<void>(p`groups/${id}/members`, { user_id: userId }),
  removeMember: (id: string, userId: string) => t.del(p`groups/${id}/members/${userId}`),
}

export const directoryRoles = {
  list: (q: PageQuery & { user_id?: string; role?: DirectoryRole } = {}) =>
    t.get<Paged<DirectoryRoleAssignment>>(`directory-roles${query({ ...q })}`),
  assign: (userId: string, role: DirectoryRole) =>
    t.post<DirectoryRoleAssignment>('directory-roles', { user_id: userId, role }),
  unassign: (id: string) => t.del(p`directory-roles/${id}`),
}
