import { describe, expect, it } from 'vitest'
import { assessmentStatusLabels } from './assessment-labels'

describe('assessment status labels', () => {
  it('uses clear evidence-based labels without implying a security guarantee', () => {
    expect(assessmentStatusLabels).toEqual({
      POTENTIALLY_AFFECTED: 'Potentially affected',
      UPSTREAM_PATCHED_VERSION: 'Upstream fixed version',
      LEGACY_UNVERIFIED: 'Legacy / vendor verification needed',
      UNKNOWN: 'Inconclusive',
    })
  })
})
