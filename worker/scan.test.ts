import { describe, expect, it, vi } from 'vitest'
import { handleScanRequest, performScan, validateScanUrl } from './scan.js'

const ALLOWED_HOST = 'developer-controlled.com'
const ALLOWED_URL = `https://${ALLOWED_HOST}/`

function response(status: number, headers: HeadersInit = {}): Response {
  return new Response(null, { status, headers })
}

function request(body: unknown): Request {
  return new Request('https://guard.example/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

describe('validateScanUrl', () => {
  it('accepts an allowlisted HTTPS URL and reduces it to the root origin', () => {
    const result = validateScanUrl(`https://${ALLOWED_HOST}/path?secret=value`, ALLOWED_HOST)

    expect(result.ok).toBe(true)
    if (result.ok) expect(result.url.href).toBe(ALLOWED_URL)
  })

  it('rejects websites outside the exact allowlist', () => {
    expect(validateScanUrl('https://other-public.com/', ALLOWED_HOST)).toMatchObject({
      ok: false,
      error: expect.stringContaining('not enabled'),
    })
  })

  it.each([
    'https://localhost/',
    'https://api.localhost/',
    'https://service.internal/',
    'https://127.0.0.1/',
    'https://10.1.2.3/',
    'https://192.168.1.10/',
    'https://169.254.10.10/',
    'https://0.0.0.0/',
    'https://192.0.2.1/',
    'https://224.0.0.1/',
    'https://[::1]/',
    'https://[fe80::1]/',
    'https://[2001:db8::1]/',
    'https://%31%32%37.0.0.1/',
    'https://2130706433/',
  ])('rejects local, internal, reserved, or IP literal target %s', (url) => {
    expect(validateScanUrl(url, ALLOWED_HOST).ok).toBe(false)
  })

  it('rejects non-HTTPS URLs', () => {
    expect(validateScanUrl(`http://${ALLOWED_HOST}/`, ALLOWED_HOST).ok).toBe(false)
  })

  it.each(['444', '8443'])('rejects custom port %s', (port) => {
    expect(validateScanUrl(`https://${ALLOWED_HOST}:${port}/`, ALLOWED_HOST).ok).toBe(false)
  })

  it('accepts explicit standard HTTPS port 443', () => {
    const result = validateScanUrl(`https://${ALLOWED_HOST}:443/`, ALLOWED_HOST)

    expect(result.ok).toBe(true)
  })

  it('rejects credentials embedded in a URL', () => {
    expect(validateScanUrl(`https://user:password@${ALLOWED_HOST}/`, ALLOWED_HOST).ok).toBe(false)
  })

  it.each(['not a URL', `https://${ALLOWED_HOST}:99999/`, `https://${ALLOWED_HOST}\\@other.com/`])(
    'rejects malformed URL %s',
    (url) => {
      expect(validateScanUrl(url, ALLOWED_HOST).ok).toBe(false)
    },
  )

  it('fails closed when the server-side allowlist is missing or invalid', () => {
    expect(validateScanUrl(ALLOWED_URL, '').ok).toBe(false)
    expect(validateScanUrl(ALLOWED_URL, `${ALLOWED_HOST},localhost`).ok).toBe(false)
    expect(validateScanUrl(ALLOWED_URL, '*.developer-controlled.com').ok).toBe(false)
  })
})

describe('handleScanRequest', () => {
  it('makes one root HEAD request without credentials and never follows redirects', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(302, { Location: 'https://elsewhere.com/' }))
    const result = await handleScanRequest(request({ url: `https://${ALLOWED_HOST}/elsewhere` }), ALLOWED_HOST, { fetcher })

    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher).toHaveBeenCalledWith(
      new URL(ALLOWED_URL),
      expect.objectContaining({
        method: 'HEAD',
        redirect: 'manual',
        headers: { Accept: '*/*' },
      }),
    )
    expect(result.status).toBe(200)
    expect(await result.json()).toMatchObject({
      status: 'INCONCLUSIVE',
      httpStatus: 302,
    })
  })

  it('does not make a network call for an unallowlisted target', async () => {
    const fetcher = vi.fn<typeof fetch>()
    const result = await handleScanRequest(request({ url: 'https://other-public.com/' }), ALLOWED_HOST, { fetcher })

    expect(result.status).toBe(403)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it.each([
    'http://developer-controlled.com/',
    'https://localhost/',
    'https://192.168.1.2/',
    'https://[::1]/',
    'https://%31%32%37.0.0.1/',
    'https://developer-controlled.com:8443/',
    'https://user@developer-controlled.com/',
    'not a URL',
  ])('does not make a network call for invalid input %s', async (url) => {
    const fetcher = vi.fn<typeof fetch>()
    const result = await handleScanRequest(request({ url }), ALLOWED_HOST, { fetcher })

    expect(result.status).toBe(400)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('fails closed and makes no request when no hostname allowlist is configured', async () => {
    const fetcher = vi.fn<typeof fetch>()
    const result = await handleScanRequest(request({ url: ALLOWED_URL }), '', { fetcher })

    expect(result.status).toBe(503)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects strict-schema violations without a network call', async () => {
    const fetcher = vi.fn<typeof fetch>()
    const result = await handleScanRequest(
      request({ url: ALLOWED_URL, extra: true }),
      ALLOWED_HOST,
      { fetcher },
    )

    expect(result.status).toBe(400)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('reports HEAD unsupported without trying a fallback', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(405))
    const result = await handleScanRequest(request({ url: ALLOWED_URL }), ALLOWED_HOST, { fetcher })

    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(result.status).toBe(200)
    expect(await result.json()).toMatchObject({
      status: 'INCONCLUSIVE',
      evidence: expect.stringContaining('No fallback request was attempted'),
    })
  })

  it('returns a generic timeout response when the outbound request times out', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('internal details', 'AbortError')))
    }))
    const result = await handleScanRequest(request({ url: ALLOWED_URL }), ALLOWED_HOST, {
      fetcher,
      timeoutMs: 5,
    })

    expect(result.status).toBe(504)
    expect(await result.json()).toEqual({ error: 'The website check timed out.' })
  })

  it('uses the existing assessment engine for a PHP header reporting an affected version', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(200, { 'X-Powered-By': 'PHP/8.2.34' }))
    const result = await handleScanRequest(request({ url: ALLOWED_URL }), ALLOWED_HOST, { fetcher })
    const payload = await result.json() as { status: string; versionAssessment: { vulnerabilities: { cveId: string; status: string }[] } }

    expect(payload.status).toBe('ASSESSED')
    expect(payload.versionAssessment.vulnerabilities).toHaveLength(2)
    expect(payload.versionAssessment.vulnerabilities.map(({ status }) => status)).toEqual([
      'POTENTIALLY_AFFECTED',
      'POTENTIALLY_AFFECTED',
    ])
  })

  it('uses the existing assessment engine for a PHP header reporting a fixed version', async () => {
    const result = await performScan(ALLOWED_URL, ALLOWED_HOST, {
      fetcher: vi.fn<typeof fetch>().mockResolvedValue(response(200, { 'X-Powered-By': 'PHP/8.4.27' })),
    })

    expect(result.status).toBe('ASSESSED')
    expect(result.versionAssessment?.vulnerabilities.map(({ status }) => status)).toEqual([
      'UPSTREAM_PATCHED_VERSION',
      'UPSTREAM_PATCHED_VERSION',
    ])
    expect(result.evidence).toContain('Headers can be spoofed')
    expect(result.evidence).toContain('vendor patches may be backported')
  })

  it('returns inconclusive when the PHP version is hidden or no PHP evidence exists', async () => {
    const hiddenVersion = await performScan(ALLOWED_URL, ALLOWED_HOST, {
      fetcher: vi.fn<typeof fetch>().mockResolvedValue(response(200, { 'X-Powered-By': 'PHP' })),
    })
    const noPhpHeader = await performScan(ALLOWED_URL, ALLOWED_HOST, {
      fetcher: vi.fn<typeof fetch>().mockResolvedValue(response(200, { Server: 'nginx' })),
    })

    expect(hiddenVersion.status).toBe('INCONCLUSIVE')
    expect(hiddenVersion.evidence).toContain('does not expose a parseable version')
    expect(noPhpHeader.status).toBe('INCONCLUSIVE')
    expect(noPhpHeader.summary).not.toContain('PHP is absent')
  })

  it('does not treat framework headers as PHP version evidence', async () => {
    const result = await performScan(ALLOWED_URL, ALLOWED_HOST, {
      fetcher: vi.fn<typeof fetch>().mockResolvedValue(response(200, { 'X-Powered-By': 'Express' })),
    })

    expect(result.status).toBe('INCONCLUSIVE')
    expect(result.phpVersion).toBeNull()
  })

  it('returns inconclusive for a spoofed or invalid PHP version', async () => {
    const result = await performScan(ALLOWED_URL, ALLOWED_HOST, {
      fetcher: vi.fn<typeof fetch>().mockResolvedValue(response(200, { 'X-Powered-By': 'PHP/8.4.27-dev' })),
    })

    expect(result.status).toBe('INCONCLUSIVE')
    expect(result.versionAssessment).toBeNull()
    expect(result.phpVersion).toBe('8.4.27-dev')
    expect(result.evidence).toContain('Headers can be spoofed')
  })
})
