import { PHP_SECURITY_ADVISORY } from './data/advisories.js'

export type AssessmentStatus =
  | 'POTENTIALLY_AFFECTED'
  | 'UPSTREAM_PATCHED_VERSION'
  | 'LEGACY_UNVERIFIED'
  | 'UNKNOWN'

export interface VulnerabilityAssessment {
  cveId: string
  title: string
  status: AssessmentStatus
  evidence: string
  recommendation: string
}

export interface VersionAssessment {
  input: string
  version: string | null
  status: AssessmentStatus
  summary: string
  recommendation: string
  confidenceExplanation: string
  vulnerabilities: VulnerabilityAssessment[]
}

interface ParsedPhpVersion {
  major: number
  minor: number
  patch: number
  normalized: string
}

function parsePhpVersion(input: string): ParsedPhpVersion | null {
  const match = /^(?:php\s+)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/i.exec(input.trim())
  if (!match) return null

  const [major, minor, patch] = match.slice(1).map(Number)
  if (![major, minor, patch].every(Number.isSafeInteger)) return null

  return {
    major,
    minor,
    patch,
    normalized: `${major}.${minor}.${patch}`,
  }
}

function compareVersions(left: ParsedPhpVersion, right: ParsedPhpVersion): number {
  for (const component of ['major', 'minor', 'patch'] as const) {
    if (left[component] < right[component]) return -1
    if (left[component] > right[component]) return 1
  }
  return 0
}

function unknownAssessment(
  input: string,
  reason: string,
): VersionAssessment {
  return {
    input,
    version: null,
    status: 'UNKNOWN',
    summary: reason,
    recommendation: 'Provide a stable PHP major.minor.patch version, then verify the running installation and package source independently.',
    confidenceExplanation: 'No upstream conclusion can be drawn because this input could not be matched to a documented stable branch.',
    vulnerabilities: PHP_SECURITY_ADVISORY.vulnerabilities.map(({ cveId, title }) => ({
      cveId,
      title,
      status: 'UNKNOWN',
      evidence: reason,
      recommendation: 'Check the PHP advisory and your vendor documentation for a verified package-specific status.',
    })),
  }
}

export function assessPhpVersion(input: string): VersionAssessment {
  const parsed = parsePhpVersion(input)
  if (!parsed) {
    return unknownAssessment(
      input,
      'The version must be a stable numeric major.minor.patch string. Prereleases and other unverifiable formats are not assessed.',
    )
  }

  if (parsed.major < 8 || (parsed.major === 8 && parsed.minor <= 1)) {
    const explanation = `PHP ${parsed.normalized} is on PHP 8.1 or an older branch. This upstream version check does not establish whether a vendor or source backport is present.`
    return {
      input,
      version: parsed.normalized,
      status: 'LEGACY_UNVERIFIED',
      summary: explanation,
      recommendation: 'Consult the distribution or package vendor for backport information, or move to a supported PHP branch.',
      confidenceExplanation: 'The reported version is outside the listed fixed-release branches; the advisory notes that older branches may receive vendor or source backports.',
      vulnerabilities: PHP_SECURITY_ADVISORY.vulnerabilities.map(({ cveId, title }) => ({
        cveId,
        title,
        status: 'LEGACY_UNVERIFIED',
        evidence: explanation,
        recommendation: 'Confirm the package-specific backport status with your vendor; do not infer vulnerable or patched status from the upstream version alone.',
      })),
    }
  }

  const matchedReleases = PHP_SECURITY_ADVISORY.vulnerabilities[0].fixedReleases
  const fixedRelease = matchedReleases.find(({ branch }) => branch === `${parsed.major}.${parsed.minor}`)
  if (!fixedRelease) {
    return unknownAssessment(
      input,
      `PHP ${parsed.normalized} is not in an upstream branch documented by this assessment. No security conclusion is made.`,
    )
  }

  const fixedVersion = parsePhpVersion(fixedRelease.version)
  if (!fixedVersion) {
    throw new Error(`Invalid fixed release in advisory data: ${fixedRelease.version}`)
  }

  const isAtOrAboveFixed = compareVersions(parsed, fixedVersion) >= 0
  const status: AssessmentStatus = isAtOrAboveFixed
    ? 'UPSTREAM_PATCHED_VERSION'
    : 'POTENTIALLY_AFFECTED'

  return {
    input,
    version: parsed.normalized,
    status,
    summary: isAtOrAboveFixed
      ? `PHP ${parsed.normalized} is at or above the first fixed upstream release ${fixedRelease.version} for its branch.`
      : `PHP ${parsed.normalized} is older than the first fixed upstream release ${fixedRelease.version} for its branch. This version is potentially affected.`
    ,
    recommendation: isAtOrAboveFixed
      ? 'Confirm that this is the version actually serving requests and check whether your vendor applies any package-specific changes.'
      : `Update to PHP ${fixedRelease.version} or a later release in the ${fixedRelease.branch} branch, or verify a vendor backport.`
    ,
    confidenceExplanation: 'This result is based on numeric comparison with the official PHP upstream fixed release. It assesses a supplied version string only and does not verify a server, package, or site.',
    vulnerabilities: PHP_SECURITY_ADVISORY.vulnerabilities.map(({ cveId, title }) => ({
      cveId,
      title,
      status,
      evidence: isAtOrAboveFixed
        ? `The official advisory lists ${fixedRelease.version} as the first fixed upstream release for PHP ${fixedRelease.branch}; the supplied version is equal to or newer than that release.`
        : `The official advisory lists ${fixedRelease.version} as the first fixed upstream release for PHP ${fixedRelease.branch}; the supplied version is older. This is version-based evidence, not exploit verification.`
      ,
      recommendation: isAtOrAboveFixed
        ? 'Verify the deployed runtime version and package provenance; this assessment does not establish that the installation is secure.'
        : `Update to ${fixedRelease.version} or later in this branch, or confirm an applicable vendor backport.`,
    })),
  }
}
