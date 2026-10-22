import { assessPhpVersion, type VersionAssessment } from '../src/assessment.js'

const MAX_BODY_BYTES = 2_048
const DEFAULT_TIMEOUT_MS = 4_000
const INTERNAL_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.test',
  '.invalid',
  '.example',
  '.onion',
  '.arpa',
  '.home.arpa',
] as const

export interface ScanOptions {
  fetcher?: typeof fetch
  timeoutMs?: number
}

export interface ScanAssessment {
  status: 'ASSESSED' | 'INCONCLUSIVE'
  phpVersion: string | null
  summary: string
  evidence: string
  httpStatus: number
  versionAssessment: VersionAssessment | null
}

interface ValidatedTarget {
  ok: true
  url: URL
}

interface InvalidTarget {
  ok: false
  error: string
}

type TargetValidation = ValidatedTarget | InvalidTarget

function isIpv4Address(hostname: string): boolean {
  const segments = hostname.split('.')
  return segments.length === 4
    && segments.every((segment) => /^(0|[1-9]\d{0,2})$/.test(segment) && Number(segment) <= 255)
}

function isPublicHostname(hostname: string): boolean {
  if (hostname.length > 253 || hostname.endsWith('.') || !hostname.includes('.')) return false
  if (hostname.includes(':') || hostname.startsWith('[') || isIpv4Address(hostname)) return false
  if (INTERNAL_HOST_SUFFIXES.some((suffix) => hostname === suffix.slice(1) || hostname.endsWith(suffix))) {
    return false
  }

  const labels = hostname.split('.')
  if (!labels.every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  ))) {
    return false
  }

  const topLevelLabel = labels.at(-1)
  return topLevelLabel !== undefined && /[a-z]/i.test(topLevelLabel)
}

function parseAllowedHosts(allowedHosts: string): Set<string> | null {
  const entries = allowedHosts.split(',').map((hostname) => hostname.trim().toLowerCase())
  if (entries.length === 0 || entries.some((hostname) => !hostname || !isPublicHostname(hostname))) {
    return null
  }
  return new Set(entries)
}

export function validateScanUrl(input: string, allowedHosts: string): TargetValidation {
  const allowlist = parseAllowedHosts(allowedHosts)
  if (!allowlist || allowlist.size === 0) {
    return { ok: false, error: 'Public website assessment is not configured for this environment.' }
  }

  const trimmed = input.trim()
  if (!trimmed || trimmed.length > 2_048 || trimmed.includes('\\')) {
    return { ok: false, error: 'Enter a valid HTTPS URL for an allowed hostname.' }
  }

  const authority = /^https:\/\/([^/?#]*)/i.exec(trimmed)?.[1]
  if (authority === undefined || authority.includes('%')) {
    return { ok: false, error: 'Enter a valid HTTPS URL for an allowed hostname.' }
  }

  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return { ok: false, error: 'Enter a valid HTTPS URL for an allowed hostname.' }
  }

  const hostname = url.hostname.toLowerCase()
  if (url.protocol !== 'https:') {
    return { ok: false, error: 'Only HTTPS URLs are accepted.' }
  }
  if (url.username || url.password || authority.includes('@')) {
    return { ok: false, error: 'URLs containing credentials are not accepted.' }
  }
  if (url.port && url.port !== '443') {
    return { ok: false, error: 'Only the standard HTTPS port 443 is accepted.' }
  }
  if (!isPublicHostname(hostname)) {
    return { ok: false, error: 'IP addresses and non-public hostnames are not accepted.' }
  }
  if (!allowlist.has(hostname)) {
    return { ok: false, error: 'This hostname is not enabled for public website assessment.' }
  }

  return {
    ok: true,
    url: new URL(`https://${hostname}/`),
  }
}

async function readLimitedBody(request: Request): Promise<string | null> {
  const contentLength = request.headers.get('content-length')
  if (contentLength && Number(contentLength) > MAX_BODY_BYTES) return null
  if (!request.body) return null

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let totalBytes = 0

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      totalBytes += value.byteLength
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
    }
  } catch {
    return null
  } finally {
    reader.releaseLock()
  }

  const body = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }

  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(body)
  } catch {
    return null
  }
}

function jsonError(message: string, status: number): Response {
  return Response.json(
    { error: message },
    {
      status,
      headers: { 'Cache-Control': 'no-store' },
    },
  )
}

function extractPhpVersion(headers: Headers): { version: string | null; evidence: string } {
  const observed: string[] = []
  let phpIndicatorFound = false

  for (const name of ['x-powered-by', 'server']) {
    const value = headers.get(name)
    if (!value || !/\bphp\b/i.test(value)) continue

    phpIndicatorFound = true
    const matches = [...value.matchAll(/\bphp(?:\/|\s+)([^\s;,]+)/gi)]
    for (const match of matches) {
      if (match[1]) observed.push(match[1])
    }
  }

  const uniqueVersions = [...new Set(observed)]
  if (uniqueVersions.length === 1) {
    return {
      version: uniqueVersions[0],
      evidence: `A PHP version string was reported in a public response header. Headers can be spoofed and do not prove the runtime or package patch status.`,
    }
  }

  if (phpIndicatorFound) {
    return {
      version: null,
      evidence: uniqueVersions.length > 1
        ? 'Public response headers contain conflicting PHP version evidence, so no version was selected.'
        : 'A public response header mentions PHP but does not expose a parseable version.',
    }
  }

  return {
    version: null,
    evidence: 'No PHP version was disclosed in the inspected public response headers. This does not establish whether the site uses PHP.',
  }
}

function makeAssessment(
  httpStatus: number,
  phpVersion: string | null,
  evidence: string,
  versionAssessment: VersionAssessment | null,
): ScanAssessment {
  if (!phpVersion || !versionAssessment || versionAssessment.status === 'UNKNOWN') {
    return {
      status: 'INCONCLUSIVE',
      phpVersion,
      summary: phpVersion
        ? 'A PHP-like version string was present, but it could not be matched to a documented stable version.'
        : 'The public response did not provide a verifiable PHP version.',
      evidence,
      httpStatus,
      versionAssessment: null,
    }
  }

  return {
    status: 'ASSESSED',
    phpVersion: versionAssessment.version,
    summary: `Preliminary version assessment for PHP ${versionAssessment.version}. This does not confirm an actual vulnerability.`,
    evidence: `${evidence} The header may be spoofed, and vendor patches may be backported without changing the upstream version number.`,
    httpStatus,
    versionAssessment,
  }
}

export async function performScan(
  input: string,
  allowedHosts: string,
  options: ScanOptions = {},
): Promise<ScanAssessment> {
  const validation = validateScanUrl(input, allowedHosts)
  if (!validation.ok) {
    throw new Error(validation.error)
  }

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const fetcher = options.fetcher ?? fetch

  try {
    const response = await fetcher(validation.url, {
      method: 'HEAD',
      redirect: 'manual',
      signal: controller.signal,
      headers: { Accept: '*/*' },
    })

    if (response.status >= 300 && response.status < 400) {
      return makeAssessment(
        response.status,
        null,
        'The site returned a redirect. Redirects are not followed by this check.',
        null,
      )
    }
    if (response.status === 405 || response.status === 501) {
      return makeAssessment(
        response.status,
        null,
        'The site does not support the non-invasive HEAD request. No fallback request was attempted.',
        null,
      )
    }
    if (!response.ok) {
      return makeAssessment(
        response.status,
        null,
        'The site did not return a successful response to the HEAD request.',
        null,
      )
    }

    const detected = extractPhpVersion(response.headers)
    const versionAssessment = detected.version
      ? assessPhpVersion(detected.version)
      : null
    return makeAssessment(response.status, detected.version, detected.evidence, versionAssessment)
  } catch {
    if (controller.signal.aborted) {
      throw new Error('The website check timed out.')
    }
    throw new Error('The website could not be checked.')
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function handleScanRequest(
  request: Request,
  allowedHosts: string,
  options: ScanOptions = {},
): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonError('Use POST to submit a scan request.', 405)
  }
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') ?? '')) {
    return jsonError('Content-Type must be application/json.', 415)
  }

  const bodyText = await readLimitedBody(request)
  if (bodyText === null) {
    return jsonError('Request body is missing, invalid, or too large.', 400)
  }

  let body: unknown
  try {
    body = JSON.parse(bodyText)
  } catch {
    return jsonError('Request body must be valid JSON.', 400)
  }

  if (
    typeof body !== 'object'
    || body === null
    || Array.isArray(body)
    || Object.keys(body).length !== 1
    || !('url' in body)
    || typeof body.url !== 'string'
  ) {
    return jsonError('Request body must contain only a string "url" property.', 400)
  }

  const validation = validateScanUrl(body.url, allowedHosts)
  if (!validation.ok) {
    const status = validation.error.includes('not configured') ? 503 : 400
    if (validation.error.includes('not enabled')) {
      return jsonError(validation.error, 403)
    }
    return jsonError(validation.error, status)
  }

  try {
    const result = await performScan(body.url, allowedHosts, options)
    return Response.json(result, {
      headers: { 'Cache-Control': 'no-store' },
    })
  } catch (error) {
    return jsonError(
      error instanceof Error && error.message === 'The website check timed out.'
        ? error.message
        : 'The website could not be checked.',
      error instanceof Error && error.message === 'The website check timed out.' ? 504 : 502,
    )
  }
}
