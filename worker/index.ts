import { handleScanRequest } from './scan.js'

interface ScanEnvironment {
  SCAN_ALLOWED_HOSTS?: string
}

export default {
  async fetch(request, env: ScanEnvironment) {
    const url = new URL(request.url)

    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') {
        return Response.json(
          { error: 'Use POST to submit a scan request.' },
          { status: 405, headers: { Allow: 'POST' } },
        )
      }

      return handleScanRequest(request, env.SCAN_ALLOWED_HOSTS ?? '')
    }

    if (url.pathname.startsWith('/api/')) {
      return Response.json({ error: 'API endpoint not found.' }, { status: 404 })
    }

    return new Response(null, { status: 404 })
  },
} satisfies ExportedHandler<Env>
