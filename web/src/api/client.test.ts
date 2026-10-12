import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from './client'

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
