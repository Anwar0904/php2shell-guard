export interface FixedRelease {
  branch: string
  version: string
}

export interface PhpVulnerabilityAdvisory {
  cveId: string
  title: string
  shortDescription: string
  fixedReleases: readonly FixedRelease[]
}

export interface PhpSecurityAdvisory {
  source: string
  lastVerified: string
  vulnerabilities: readonly PhpVulnerabilityAdvisory[]
}

const fixedReleases = [
  { branch: '8.2', version: '8.2.35' },
  { branch: '8.3', version: '8.3.36' },
  { branch: '8.4', version: '8.4.27' },
  { branch: '8.5', version: '8.5.12' },
] as const satisfies readonly FixedRelease[]

export const PHP_SECURITY_ADVISORY: PhpSecurityAdvisory = {
  source: 'https://www.php.net/archive/2026.php#2026-10-21-5',
  lastVerified: '2026-10-21',
  vulnerabilities: [
    {
      cveId: 'CVE-2026-109618',
      title: 'Remote code execution via out-of-memory corruption',
      shortDescription: 'The PHP advisory describes memory allocation failure handling that can leave internal request data partially initialized.',
      fixedReleases,
    },
    {
      cveId: 'CVE-2026-109619',
      title: 'Remote code execution via stale global state',
      shortDescription: 'The PHP advisory describes request-owned internal state that may be used after its backing memory has been freed.',
      fixedReleases,
    },
  ],
}
