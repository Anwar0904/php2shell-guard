import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  analyzeDiagnosticReport,
  DiagnosticReportValidationError,
  MAX_DIAGNOSTIC_REPORT_BYTES,
  parseDiagnosticReport,
  type PhpDiagnosticReport,
} from './diagnostic'

const validReport: PhpDiagnosticReport = {
  schemaVersion: 1,
  phpVersion: '8.2.34',
  sapi: 'cli',
  osFamily: 'Linux',
  diagnosticTimestamp: '2026-10-22T09:58:00Z',
  runtimeContext: 'cli',
}

function reportJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ ...validReport, ...overrides })
}

describe('PHP CLI diagnostic report validation', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('accepts a valid CLI report and assesses both supported CVEs', () => {
    const result = analyzeDiagnosticReport(reportJson())

    expect(result.report).toEqual(validReport)
    expect(result.assessment.status).toBe('POTENTIALLY_AFFECTED')
    expect(result.assessment.vulnerabilities).toHaveLength(2)
  })

  it.each([
    ['8.2.34', 'POTENTIALLY_AFFECTED'],
    ['8.4.27', 'UPSTREAM_PATCHED_VERSION'],
    ['8.1.30', 'LEGACY_UNVERIFIED'],
    ['8.6.0', 'UNKNOWN'],
  ] as const)('reuses assessment logic for PHP %s', (phpVersion, expectedStatus) => {
    const result = analyzeDiagnosticReport(reportJson({ phpVersion }))

    expect(result.assessment.status).toBe(expectedStatus)
    expect(result.assessment.vulnerabilities.map(({ status }) => status))
      .toEqual([expectedStatus, expectedStatus])
  })

  it.each([
    ['missing field', { runtimeContext: undefined }],
    ['unexpected field', { apiKey: 'sensitive-value' }],
    ['unsupported schema version', { schemaVersion: 2 }],
    ['invalid PHP version', { phpVersion: '8.2' }],
    ['PHP prerelease', { phpVersion: '8.2.35RC1' }],
    ['unsafe PHP version component', { phpVersion: '8.2.999999999999999999999' }],
    ['invalid SAPI', { sapi: 'fpm-fcgi' }],
    ['invalid runtime context', { runtimeContext: 'web' }],
    ['unsupported OS family', { osFamily: 'Cloud' }],
    ['invalid timestamp', { diagnosticTimestamp: 'not-a-date' }],
    ['impossible timestamp', { diagnosticTimestamp: '2026-02-30T12:00:00Z' }],
    ['zero year timestamp', { diagnosticTimestamp: '0000-01-01T00:00:00Z' }],
    ['timestamp with a non-UTC offset', { diagnosticTimestamp: '2026-10-22T09:58:00+05:00' }],
  ])('rejects %s', (_description, overrides) => {
    expect(() => parseDiagnosticReport(reportJson(overrides))).toThrow(DiagnosticReportValidationError)
  })

  it('rejects malformed JSON', () => {
    expect(() => parseDiagnosticReport('{"schemaVersion":')).toThrow('not valid JSON')
  })

  it('rejects reports larger than the configured size limit before parsing', () => {
    const oversized = ' '.repeat(MAX_DIAGNOSTIC_REPORT_BYTES + 1)

    expect(() => parseDiagnosticReport(oversized)).toThrow('too large')
  })

  it('rejects strings that could contain markup or executable text', () => {
    expect(() => parseDiagnosticReport(reportJson({ phpVersion: '<img src=x onerror=alert(1)>' })))
      .toThrow('stable numeric PHP')
  })

  it('does not make a network request or upload report content during analysis', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    analyzeDiagnosticReport(reportJson())

    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
