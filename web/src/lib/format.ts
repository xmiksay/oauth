/** Locale date-time for an RFC 3339 timestamp; `—` for null. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** Human duration for a TTL in seconds (`1 h`, `14 d`). */
export function formatDuration(secs: number): string {
  if (secs % 86400 === 0) return `${secs / 86400} d`
  if (secs % 3600 === 0) return `${secs / 3600} h`
  if (secs % 60 === 0) return `${secs / 60} min`
  return `${secs} s`
}

/** One URI per non-empty line. */
export function parseLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
}

export const PASSWORD_MIN = 12
export const PASSWORD_MAX = 256

/** Client-side check of the server's password rules; `null` when acceptable. */
export function passwordProblem(pw: string, confirm?: string): string | null {
  if (pw.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`
  if (pw.length > PASSWORD_MAX) return `Use at most ${PASSWORD_MAX} characters.`
  if (confirm !== undefined && pw !== confirm) return 'The passwords do not match.'
  return null
}
