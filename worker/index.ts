import { handleScanRequest } from './scan.js'

interface ScanEnvironment {
  SCAN_ALLOWED_HOSTS?: string
}

function withApiSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers)
  headers.set('Cache-Control', 'no-store')
  headers.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
  headers.set('Referrer-Policy', 'no-referrer')
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('X-Frame-Options', 'DENY')

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

export default {
  async fetch(request, env: ScanEnvironment) {
    const url = new URL(request.url)

    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') {
        return withApiSecurityHeaders(Response.json(
          { error: 'Use POST to submit a scan request.' },
          { status: 405, headers: { Allow: 'POST' } },
        ))
      }

      return withApiSecurityHeaders(
        await handleScanRequest(request, env.SCAN_ALLOWED_HOSTS ?? ''),
      )
    }

    if (url.pathname.startsWith('/api/')) {
      return withApiSecurityHeaders(Response.json({ error: 'API endpoint not found.' }, { status: 404 }))
    }

    return new Response(null, { status: 404 })
  },
} satisfies ExportedHandler<Env>
