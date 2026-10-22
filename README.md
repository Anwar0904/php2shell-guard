# PHP2Shell Guard

PHP2Shell Guard is an open-source security assessment tool. Milestone 1 provides an offline comparison of a user-entered PHP version with official upstream releases fixing two PHP security advisories.

## Supported checks

The version assessment covers:

- CVE-2026-109618
- CVE-2026-109619

The official PHP advisory lists these upstream fixed releases:

| PHP branch | First fixed upstream release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 8.1 and older are reported as legacy/unverified because vendor and source backports may exist and need separate confirmation. Unknown branches, prerelease versions, and malformed or unverifiable strings do not receive a positive security verdict.

**A version comparison is not vulnerability testing.** It does not contact or inspect a website, establish the PHP runtime in use, confirm vendor backports, or prove an installation secure. A version listed as upstream-fixed is evidence about the version string only.

## Official advisory

[PHP security advisory — 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)

The advisory data in this project records this source and was last verified on **2026-10-21**.

## Installation and local development

Requirements: Node.js and npm compatible with the versions in the project toolchain.

```sh
npm install
npm run dev
```

Vite prints a local development URL when the server is ready. The application performs no assessment network requests.

## Testing and validation

```sh
npm test
npm run build
npm run lint
```

The production build includes the configured TypeScript project checks before running Vite.

## Current limitations

- Assessment is based only on the version string manually provided by the user.
- Only upstream fixed release comparisons for PHP branches 8.2 through 8.5 are included.
- Vendor backports and distributions' package revisions are not inferred.
- The app does not assess URLs, verify domains, or test servers.
- It does not perform exploit-based confirmation or invoke third-party vulnerability scanners.

## Planned functionality

The following are **not implemented** in Milestone 1:

1. Public URL-based preliminary assessments.
2. Verified server-side assessments.

No deployment, authentication, database, or external scanning integration is included in this milestone.
