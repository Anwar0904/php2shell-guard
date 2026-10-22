import { describe, expect, it } from 'vitest'
import worker from './index.js'

describe('Worker API security headers', () => {
  it('returns no-store and restrictive security headers for scan responses', async () => {
    const response = await worker.fetch(
      new Request('https://guard.example/api/scan', { method: 'GET' }),
      {},
    )

    expect(response.status).toBe(405)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'none'")
    expect(response.headers.get('referrer-policy')).toBe('no-referrer')
    expect(response.headers.get('x-content-type-options')).toBe('nosniff')
    expect(response.headers.get('x-frame-options')).toBe('DENY')
    expect(response.headers.get('allow')).toBe('POST')
  })

  it('applies security headers to unknown API paths', async () => {
    const response = await worker.fetch(
      new Request('https://guard.example/api/unknown'),
      {},
    )

    expect(response.status).toBe(404)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('x-content-type-options')).toBe('nosniff')
  })

  it('keeps website checks disabled when no server-side allowlist is configured', async () => {
    const response = await worker.fetch(
      new Request('https://guard.example/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://developer-controlled.com/' }),
      }),
      {},
    )

    expect(response.status).toBe(503)
    expect(await response.json()).toEqual({
      error: 'Public website assessment is not configured for this environment.',
    })
    expect(response.headers.get('cache-control')).toBe('no-store')
  })
})
