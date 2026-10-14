// The signed-in user's self-service (`/api/v1/me/…` on the tenant's host).
import { p, t } from './management'
import type {
  Items,
  MyConsent,
  NotificationPreference,
  NotificationSettings,
  RecoveryCodes,
  Session,
  TotpEnrollment,
  Me,
} from './types'

export const me = {
  get: () => t.get<Me>('me'),
  update: (body: { display_name: string }) => t.patch<Me>('me', body),
  changePassword: (current: string, next: string) =>
    t.post<void>('me/change-password', { current_password: current, new_password: next }),
  beginTotp: (password: string) => t.post<TotpEnrollment>('me/totp', { password }),
  confirmTotp: (code: string) => t.post<RecoveryCodes>('me/totp/confirm', { code }),
  removeTotp: (password: string) => t.del('me/totp', { password }),
  regenerateRecoveryCodes: (password: string) =>
    t.post<RecoveryCodes>('me/recovery-codes', { password }),
  sessions: () => t.get<Items<Session>>('me/sessions'),
  revokeSession: (id: string) => t.del(p`me/sessions/${id}`),
  revokeAllSessions: () => t.post<void>('me/sessions/revoke-all'),
  consents: () => t.get<Items<MyConsent>>('me/consents'),
  revokeConsent: (id: string) => t.del(p`me/consents/${id}`),
  sendVerification: () => t.post<{ sent: boolean }>('me/verify-email'),
  /** The link goes to `newEmail`; the address changes only once it's opened. */
  changeEmail: (newEmail: string, password: string) =>
    t.post<{ sent: boolean }>('me/email', { new_email: newEmail, password }),
  notifications: () => t.get<NotificationSettings>('me/notifications'),
  updateNotifications: (items: NotificationPreference[]) =>
    t.put<NotificationSettings>('me/notifications', { items }),
}
