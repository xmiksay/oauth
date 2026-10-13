/** Error thrown for any non-2xx response; `body` is parsed JSON when possible, else text. */
export class ApiError extends Error {
  readonly status: number
  readonly body: unknown
  /** Seconds from `Retry-After` (429), when the server sent one. */
  readonly retryAfter: number | null

  constructor(status: number, body: unknown, retryAfter: number | null = null) {
    super(`API request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
    this.retryAfter = retryAfter
  }

  /** The `error` code of a `{ error, error_description }` body. */
  get code(): string | null {
    return field(this.body, 'error')
  }

  get description(): string | null {
    return field(this.body, 'error_description')
  }
}

function field(body: unknown, key: string): string | null {
  if (typeof body !== 'object' || body === null) return null
  const value = (body as Record<string, unknown>)[key]
  return typeof value === 'string' ? value : null
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  headers?: Record<string, string>
  signal?: AbortSignal
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return undefined
  if (res.headers.get('content-type')?.includes('json')) {
    try {
      return JSON.parse(text)
    } catch {
      return text
    }
  }
  return text
}

function parseRetryAfter(res: Response): number | null {
  const raw = res.headers.get('retry-after')
  if (raw === null) return null
  const secs = Number.parseInt(raw, 10)
  return Number.isFinite(secs) && secs >= 0 ? secs : null
}

/** Same-origin JSON request (cookies included). `path` is absolute, e.g. `/api/v1/tenants`. */
export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers }
  const init: RequestInit = {
    method: opts.method ?? 'GET',
    headers,
    signal: opts.signal,
    credentials: 'same-origin',
  }
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(opts.body)
  }

  const res = await fetch(path, init)
  const body = await parseBody(res)
  if (!res.ok) throw new ApiError(res.status, body, parseRetryAfter(res))
  return body as T
}

type NoBody = Omit<RequestOptions, 'method' | 'body'>

export const api = {
  get: <T>(path: string, opts?: NoBody) => request<T>(path, { ...opts, method: 'GET' }),
  post: <T>(path: string, body?: unknown, opts?: NoBody) =>
    request<T>(path, { ...opts, method: 'POST', body }),
  put: <T>(path: string, body?: unknown, opts?: NoBody) =>
    request<T>(path, { ...opts, method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown, opts?: NoBody) =>
    request<T>(path, { ...opts, method: 'PATCH', body }),
  delete: <T>(path: string, body?: unknown, opts?: NoBody) =>
    request<T>(path, { ...opts, method: 'DELETE', body }),
}

/** A user-facing sentence for any error a request can throw. */
export function errorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return err instanceof TypeError
      ? 'Could not reach the server. Check your connection and try again.'
      : 'Something went wrong. Please try again.'
  }
  switch (err.status) {
    case 401:
      return 'Your session has expired. Please sign in again.'
    case 403:
      return err.description ?? "You don't have permission to do this."
    case 404:
      return 'The requested item was not found. It may have been deleted.'
    case 429:
      return err.retryAfter !== null
        ? `Too many attempts. Try again in ${err.retryAfter} seconds.`
        : 'Too many attempts. Try again later.'
  }
  if (err.status >= 500) return 'The server ran into a problem. Please try again.'
  return err.description ?? `Request failed (${err.status}).`
}

/** `?a=1&b=x` from defined, non-empty values only. */
export function query(params: Record<string, string | number | null | undefined>): string {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') qs.set(key, String(value))
  }
  const s = qs.toString()
  return s ? `?${s}` : ''
}
