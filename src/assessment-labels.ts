import type { AssessmentStatus } from './assessment'

export const assessmentStatusLabels: Record<AssessmentStatus, string> = {
  POTENTIALLY_AFFECTED: 'Potentially affected',
  UPSTREAM_PATCHED_VERSION: 'Upstream fixed version',
  LEGACY_UNVERIFIED: 'Legacy / vendor verification needed',
  UNKNOWN: 'Inconclusive',
}
