import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, errorMessage, query } from './client'

function mockFetch(status: number, body: string, contentType = 'application/json') {
  const fn = vi.fn().mockResolvedValue(
    new Response(body || null, { status, headers: { 'content-type': contentType } }),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('api client', () => {
  it('returns parsed JSON on success', async () => {
    const fetchMock = mockFetch(200, '{"id":1,"name":"x"}')
    const data = await api.get<{ id: number; name: string }>('/api/v1/things')
    expect(data).toEqual({ id: 1, name: 'x' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/things',
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('serialises the body and sets content-type on POST', async () => {
    const fetchMock = mockFetch(201, '{"ok":true}')
    await api.post('/api/v1/things', { a: 1 })
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(init.method).toBe('POST')
    expect(init.body).toBe('{"a":1}')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('returns undefined for an empty body', async () => {
    mockFetch(204, '')
    await expect(api.delete('/api/v1/things/1')).resolves.toBeUndefined()
  })

  it('throws ApiError with status and JSON body on error', async () => {
    mockFetch(400, '{"error":"invalid_request"}')
    const err = await api.get('/api/v1/things').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(400)
    expect((err as ApiError).body).toEqual({ error: 'invalid_request' })
  })

  it('throws ApiError with text body for non-JSON errors', async () => {
    mockFetch(502, 'Bad Gateway', 'text/plain')
    const err = await api.get('/api/v1/things').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(502)
    expect((err as ApiError).body).toBe('Bad Gateway')
  })
})

describe('error details', () => {
  it('exposes error code, description and Retry-After', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('{"error":"rate_limited","error_description":"slow down"}', {
          status: 429,
          headers: { 'content-type': 'application/json', 'retry-after': '42' },
        }),
      ),
    )
    const err = (await api.get('/x').catch((e: unknown) => e)) as ApiError
    expect([err.code, err.description, err.retryAfter]).toEqual(['rate_limited', 'slow down', 42])
    expect(errorMessage(err)).toBe('Too many attempts. Try again in 42 seconds.')
  })

  it('maps statuses to user-facing messages', () => {
    expect(errorMessage(new ApiError(403, { error: 'forbidden' }))).toMatch(/permission/)
    expect(errorMessage(new ApiError(409, { error: 'conflict', error_description: 'taken' }))).toBe(
      'taken',
    )
    expect(errorMessage(new ApiError(500, 'x'))).toMatch(/server/)
    expect(errorMessage(new TypeError('fetch failed'))).toMatch(/reach the server/)
  })
})

describe('query', () => {
  it('drops empty values and encodes the rest', () => {
    expect(query({ a: 1, b: '', c: null, d: undefined, e: 'x y' })).toBe('?a=1&e=x+y')
    expect(query({})).toBe('')
  })
})
