import { assessPhpVersion, type VersionAssessment } from './assessment'

export const DIAGNOSTIC_SCHEMA_VERSION = 1
export const MAX_DIAGNOSTIC_REPORT_BYTES = 16 * 1024

export interface PhpDiagnosticReport {
  schemaVersion: typeof DIAGNOSTIC_SCHEMA_VERSION
  phpVersion: string
  sapi: 'cli'
  osFamily: 'Windows' | 'BSD' | 'Darwin' | 'Solaris' | 'Linux' | 'Unknown'
  diagnosticTimestamp: string
  runtimeContext: 'cli'
}

export interface DiagnosticAnalysis {
  report: PhpDiagnosticReport
  assessment: VersionAssessment
}

export class DiagnosticReportValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DiagnosticReportValidationError'
  }
}

const reportFields = [
  'schemaVersion',
  'phpVersion',
  'sapi',
  'osFamily',
  'diagnosticTimestamp',
  'runtimeContext',
] as const

const phpVersionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOsFamily(value: unknown): value is PhpDiagnosticReport['osFamily'] {
  return value === 'Windows'
    || value === 'BSD'
    || value === 'Darwin'
    || value === 'Solaris'
    || value === 'Linux'
    || value === 'Unknown'
}

function isStablePhpVersion(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = phpVersionPattern.exec(value)
  if (!match) return false
  return match.slice(1).every((component) => Number.isSafeInteger(Number(component)))
}

function isValidUtcTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    return false
  }
  if (Number(value.slice(0, 4)) === 0) return false

  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) return false

  try {
    return new Date(timestamp).toISOString() === value.replace(/Z$/, '.000Z')
  } catch {
    return false
  }
}

export function parseDiagnosticReport(json: string): PhpDiagnosticReport {
  if (new TextEncoder().encode(json).byteLength > MAX_DIAGNOSTIC_REPORT_BYTES) {
    throw new DiagnosticReportValidationError(
      `The report is too large. Select a JSON file no larger than ${MAX_DIAGNOSTIC_REPORT_BYTES / 1024} KB.`,
    )
  }

  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    throw new DiagnosticReportValidationError('The selected file is not valid JSON.')
  }

  if (!isRecord(value)) {
    throw new DiagnosticReportValidationError('The report must be a JSON object.')
  }

  const actualFields = Object.keys(value)
  if (
    actualFields.length !== reportFields.length
    || reportFields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new DiagnosticReportValidationError(
      'The report contains missing or unexpected fields. Use an unmodified report from the diagnostic script.',
    )
  }

  if (value.schemaVersion !== DIAGNOSTIC_SCHEMA_VERSION) {
    throw new DiagnosticReportValidationError('This diagnostic report schema version is not supported.')
  }
  if (!isStablePhpVersion(value.phpVersion)) {
    throw new DiagnosticReportValidationError('The report must contain a stable numeric PHP major.minor.patch version.')
  }
  if (value.sapi !== 'cli' || value.runtimeContext !== 'cli') {
    throw new DiagnosticReportValidationError('Only reports identifying the PHP CLI runtime are supported.')
  }
  if (!isOsFamily(value.osFamily)) {
    throw new DiagnosticReportValidationError('The report contains an unsupported operating-system family.')
  }
  if (!isValidUtcTimestamp(value.diagnosticTimestamp)) {
    throw new DiagnosticReportValidationError('The report must contain a valid UTC diagnostic timestamp.')
  }

  return {
    schemaVersion: DIAGNOSTIC_SCHEMA_VERSION,
    phpVersion: value.phpVersion,
    sapi: 'cli',
    osFamily: value.osFamily,
    diagnosticTimestamp: value.diagnosticTimestamp,
    runtimeContext: 'cli',
  }
}

export function analyzeDiagnosticReport(json: string): DiagnosticAnalysis {
  const report = parseDiagnosticReport(json)
  return {
    report,
    assessment: assessPhpVersion(report.phpVersion),
  }
}
