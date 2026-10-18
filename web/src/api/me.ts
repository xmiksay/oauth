// The signed-in user's self-service (`/api/v1/me/…` on the tenant's host).
import { p, t } from './management'
import type {
  Items,
  MyConsent,
  NotificationPreference,
  NotificationSettings,
  Passkey,
  PasskeyCreationOptions,
  PasskeyRegistration,
  PasskeyRequestOptions,
  Reauth,
  RecoveryCodes,
  Session,
  TelegramLink,
  TelegramStatus,
  TotpEnrollment,
  Me,
} from './types'

export const me = {
  get: () => t.get<Me>('me'),
  update: (body: { display_name: string }) => t.patch<Me>('me', body),
  /** With a passkey, a user without a password sets their first one. */
  changePassword: (next: string, reauth: Reauth) =>
    t.post<void>(
      'me/change-password',
      'password' in reauth
        ? { new_password: next, current_password: reauth.password }
        : { new_password: next, passkey: reauth.passkey },
    ),
  beginTotp: (reauth: Reauth) => t.post<TotpEnrollment>('me/totp', reauth),
  confirmTotp: (code: string) => t.post<RecoveryCodes>('me/totp/confirm', { code }),
  removeTotp: (reauth: Reauth) => t.del('me/totp', reauth),
  regenerateRecoveryCodes: (reauth: Reauth) =>
    t.post<RecoveryCodes>('me/recovery-codes', reauth),
  /** A challenge for passkey re-authentication (409 when the user has no passkey). */
  reauthOptions: () => t.post<PasskeyRequestOptions>('me/reauth/options'),
  passkeys: () => t.get<Items<Passkey>>('me/passkeys'),
  passkeyOptions: (reauth: Reauth) => t.post<PasskeyCreationOptions>('me/passkeys/options', reauth),
  addPasskey: (credential: PasskeyRegistration, name?: string) =>
    t.post<Passkey>('me/passkeys', name ? { credential, name } : { credential }),
  renamePasskey: (id: string, name: string) => t.patch<Passkey>(p`me/passkeys/${id}`, { name }),
  removePasskey: (id: string, reauth: Reauth) => t.del(p`me/passkeys/${id}`, reauth),
  sessions: () => t.get<Items<Session>>('me/sessions'),
  revokeSession: (id: string) => t.del(p`me/sessions/${id}`),
  revokeAllSessions: () => t.post<void>('me/sessions/revoke-all'),
  consents: () => t.get<Items<MyConsent>>('me/consents'),
  revokeConsent: (id: string) => t.del(p`me/consents/${id}`),
  sendVerification: () => t.post<{ sent: boolean }>('me/verify-email'),
  /** The link goes to `newEmail`; the address changes only once it's opened. */
  changeEmail: (newEmail: string, reauth: Reauth) =>
    t.post<{ sent: boolean }>('me/email', { new_email: newEmail, ...reauth }),
  /** 404 when the server has no Telegram bot. */
  getTelegram: () => t.get<TelegramStatus>('me/telegram'),
  /** A fresh deep link replaces any unused one; linking again replaces the chat. */
  linkTelegram: (reauth: Reauth) => t.post<TelegramLink>('me/telegram/link', reauth),
  unlinkTelegram: (reauth: Reauth) => t.del('me/telegram', reauth),
  notifications: () => t.get<NotificationSettings>('me/notifications'),
  updateNotifications: (items: NotificationPreference[]) =>
    t.put<NotificationSettings>('me/notifications', { items }),
}
