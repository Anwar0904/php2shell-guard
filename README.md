# PHP2Shell Guard

[![CI](https://github.com/Anwar0904/php2shell-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Anwar0904/php2shell-guard/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.2-61DAFB?logo=react&logoColor=white)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4.x-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-Worker%20runtime-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/workers/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

A focused, low-noise PHP security assessment tool for upstream version evidence and safe, developer-controlled website header checks.

## Why this project exists

PHP2Shell Guard was created to help operators and developers assess whether a PHP version is aligned with official upstream fixed releases for two critical PHP advisories without claiming a site is safe or vulnerable based on a single header. The project is intentionally conservative: it favors evidence-driven analysis, clear limits, and developer-controlled checks over broad public scanning.

## What is currently implemented

- Offline comparison of a user-entered PHP version against official upstream fixed releases for:
  - CVE-2026-109618
  - CVE-2026-109619
- Allowlisted public-header check for exact, developer-controlled HTTPS hostnames.
- Strict input validation and fail-closed behavior for malformed, internal, IP-based, credential-bearing, and non-allowlisted targets.
- Unit tests covering version assessment logic and mocked Worker scan behavior.

## Supported CVEs and official references

The project currently covers the advisories announced by the PHP project on 2026-10-21:

- CVE-2026-109618 — [PHP Security Advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- CVE-2026-109619 — [PHP Security Advisory](https://www.php.net/archive/2026.php#2026-10-21-5)

Official upstream fixed releases recorded in the project:

| PHP branch | First fixed upstream release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

## How version assessment works

The project validates a PHP version string as a stable `major.minor.patch` value, compares it against the first upstream fixed release for that branch, and returns one of the following statuses:

- `POTENTIALLY_AFFECTED`
- `UPSTREAM_PATCHED_VERSION`
- `LEGACY_UNVERIFIED`
- `UNKNOWN`

This is strictly version-evidence logic. It does not validate that an application is actually running that version or that a package includes a vendor backport. Unsupported branches, malformed values, prereleases, and unknown branches are treated conservatively as `UNKNOWN` or `LEGACY_UNVERIFIED` rather than receiving a positive verdict.

## Assessment confidence and limits

Confidence is intentionally limited to the data being evaluated:

- A version match reflects upstream release data, not live runtime verification.
- A public `X-Powered-By` or `Server` header is not proof of the actual PHP version or patch status.
- Vendor backports can fix a package while leaving the upstream PHP version unchanged.
- The tool never confirms exploitation or a successful vulnerability in a live site.

## Screenshot

![Current application UI](./src/assets/hero.png)

## Quick start

```sh
npm install
npm run dev
```

Then open the local Vite URL in a browser.

## Local development

```sh
npm install
npm run dev
```

For the allowlisted website checker, add a local `.dev.vars` file with exact hostnames you control:

```dotenv
SCAN_ALLOWED_HOSTS=staging.yourdomain.com
```

Do not add arbitrary public URLs or wildcard entries. The check fails closed when the allowlist is absent or invalid.

## Available npm commands

```sh
npm test
npm run build
npm run lint
npm run dev
npm run preview
npm run deploy
npm run cf-typegen
```

## Technology stack

- React 19
- TypeScript
- Vite 8
- Tailwind CSS 4
- Cloudflare Workers
- Vitest

## Project structure

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/
├── src/
│   ├── App.css
│   ├── App.tsx
│   ├── assessment.test.ts
│   ├── assessment.ts
│   ├── data/
│   ├── index.css
│   ├── main.tsx
│   └── assets/
├── worker/
│   ├── index.ts
│   ├── scan.ts
│   └── scan.test.ts
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── eslint.config.js
├── index.html
├── package.json
├── package-lock.json
├── tsconfig.app.json
├── tsconfig.node.json
├── tsconfig.worker.json
├── vite.config.ts
├── vitest.config.ts
├── wrangler.jsonc
└── worker-configuration.d.ts
```

## Supported and planned features

| Status | Feature |
| --- | --- |
| Implemented | Offline PHP version assessment for the two supported CVEs |
| Implemented | Public website check against exact allowlisted HTTPS hostnames |
| Implemented | Strict input validation and fail-closed scanning logic |
| Planned | Verified server-side runtime diagnostics |
| Planned | Public hosted deployment |
| Planned | Broader public URL scanning and automated verification workflows |

## Current limitations

- Public checks are deliberately restricted to exact, explicitly allowlisted hostnames.
- The website checker operates on public headers only and does not verify the actual runtime or vendor packages.
- Arbitrary public URL submissions remain disabled.
- This project does not perform vulnerability confirmation or exploit testing.
- It does not persist scan history or add user accounts.

## Security considerations

This project intentionally avoids unsafe scanning behavior:

- No arbitrary public scanning.
- No payload-based exploit testing.
- No password, auth, or third-party API integration.
- No HTML crawling or content downloads during the public-check flow.
- No redirect following in the site check.

The app is designed as an evidence-focused, low-risk assessment utility, not as a general reconnaissance tool.

## Roadmap

| Phase | Status | Notes |
| --- | --- | --- |
| Milestone 1 | Completed | Offline PHP advisory comparison and version evidence checks |
| Milestone 2 | Implemented in code | Allowlisted public-header checks with fail-closed validation |
| Verified server diagnostics | Planned | Requires a fully reviewed and scope-limited runtime verification design |
| Hosted public deployment | Planned | Not yet implemented |

## Contributing

Contributions are welcome when they improve the project’s quality, clarity, and security posture. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening an issue or pull request.

## License

This project is licensed under the [MIT License](./LICENSE).

## Maintainer

The repository is maintained by the GitHub owner: [@Anwar0904](https://github.com/Anwar0904).

## Security reporting

Please review [SECURITY.md](./SECURITY.md) before reporting a vulnerability.
