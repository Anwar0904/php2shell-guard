import { describe, expect, it } from 'vitest'
import { assessPhpVersion, type AssessmentStatus } from './assessment'

describe('assessPhpVersion', () => {
  it.each([
    ['8.2.34', 'POTENTIALLY_AFFECTED'],
    ['8.2.35', 'UPSTREAM_PATCHED_VERSION'],
    ['8.3.35', 'POTENTIALLY_AFFECTED'],
    ['8.3.36', 'UPSTREAM_PATCHED_VERSION'],
    ['8.4.26', 'POTENTIALLY_AFFECTED'],
    ['8.4.27', 'UPSTREAM_PATCHED_VERSION'],
    ['8.4.30', 'UPSTREAM_PATCHED_VERSION'],
    ['8.5.11', 'POTENTIALLY_AFFECTED'],
    ['8.5.12', 'UPSTREAM_PATCHED_VERSION'],
    ['8.1.30', 'LEGACY_UNVERIFIED'],
    ['8.6.0', 'UNKNOWN'],
  ] as const satisfies readonly [string, AssessmentStatus][])(
    'assesses %s as %s for both CVEs',
    (version, expectedStatus) => {
      const result = assessPhpVersion(version)

      expect(result.status).toBe(expectedStatus)
      expect(result.vulnerabilities).toHaveLength(2)
      expect(result.vulnerabilities.map(({ status }) => status)).toEqual([
        expectedStatus,
        expectedStatus,
      ])
    },
  )

  it.each([
    '8.2',
    '8.2.35.1',
    '8.x.35',
    '8.2.35-dev',
    '8.2.35RC1',
    '8.2.999999999999999999999',
  ])('does not assign a positive verdict to invalid or unverifiable version %s', (version) => {
    const result = assessPhpVersion(version)

    expect(result.status).toBe('UNKNOWN')
    expect(result.version).toBeNull()
    expect(result.vulnerabilities.every(({ status }) => status === 'UNKNOWN')).toBe(true)
  })

  it('compares numeric version components rather than lexicographic strings', () => {
    const result = assessPhpVersion('8.2.100')

    expect(result.status).toBe('UPSTREAM_PATCHED_VERSION')
    expect(result.version).toBe('8.2.100')
  })

  it('accepts a conventional PHP prefix and surrounding whitespace', () => {
    const result = assessPhpVersion(' PHP 8.2.35 ')

    expect(result.version).toBe('8.2.35')
    expect(result.status).toBe('UPSTREAM_PATCHED_VERSION')
  })

  it('keeps fixed-version results explicitly limited to version evidence', () => {
    const result = assessPhpVersion('8.4.27')

    expect(result.confidenceExplanation).toContain('does not verify a server')
    expect(result.recommendation).toContain('Confirm')
    expect(result.vulnerabilities[0].recommendation).toContain('does not establish that the installation is secure')
  })
})
