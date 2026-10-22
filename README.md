# PHP2Shell Guard

[![CI](https://github.com/Anwar0904/php2shell-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Anwar0904/php2shell-guard/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0%2B-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.2-61DAFB?logo=react&logoColor=white)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4.x-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-Worker%20runtime-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/workers/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

A focused PHP security assessment utility for upstream version evidence, allowlisted website headers, and local CLI diagnostics.

## Why this project exists

PHP2Shell Guard was created to help operators and developers assess whether a PHP version is aligned with official upstream fixed releases for two critical PHP advisories without claiming a site is safe or vulnerable based on a single header. The project is intentionally conservative: it favors evidence-driven analysis, clear limits, and developer-controlled checks over broad public scanning.

## What is currently implemented

- A responsive interface with keyboard-accessible tabs for each assessment tool.
- Offline comparison of a user-entered PHP version against official upstream fixed releases for:
  - CVE-2026-109618
  - CVE-2026-109619
- Allowlisted public-header check for exact, developer-controlled HTTPS hostnames.
- A local, read-only PHP CLI diagnostic whose small JSON report is validated and assessed entirely in the browser.
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

## Local PHP server diagnostic

The diagnostic is an optional PHP CLI script for infrastructure you own. It reads only `PHP_VERSION`, `PHP_SAPI`, `PHP_OS_FAMILY` (or `Unknown` on older PHP versions without that constant), and the current UTC timestamp. The report also identifies schema version 1 and the `cli` runtime context.

From the repository root, run:

```sh
php tools/php-diagnostic.php > php-report.json
```

Review `php-report.json` locally before sharing it. You can also use **Download diagnostic script** in the application, review the downloaded source, run it with PHP CLI, and import the resulting JSON in **Server Diagnostic**. The browser rejects files over 16 KB, malformed JSON, unsupported schema versions, unexpected fields, invalid versions, non-CLI SAPI values, and invalid timestamps.

The report is parsed with the browser File API and assessed locally using the existing version assessment engine. Its contents are not uploaded, stored, or sent as telemetry. The script does not make network requests, execute shell commands, inspect configuration, or modify files. It must not be exposed or invoked as a web endpoint.

This is **local CLI diagnostic evidence**, not authenticated evidence: an imported JSON file can be altered. CLI PHP may differ from the PHP runtime serving web traffic. The result does not verify vendor backports, prove a vulnerability, or establish that a system is secure. Check each CVE's official PHP advisory and your package vendor's update guidance.

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

The allowlist is empty by default. Only configure exact hostnames that you control and have explicitly approved for this check. URL checks are enforced by the Worker; client-side form validation is not a security boundary.

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

## Cloudflare Workers deployment

Deployment is a manual maintainer action; the project does not deploy automatically. The current Worker and static SPA configuration is in [wrangler.jsonc](./wrangler.jsonc), and the GitHub Actions workflow does not deploy.

1. Review the source and required security settings for your environment.
2. Install dependencies and run validation:

   ```sh
   npm ci
   npm test
   npm run build
   npm run lint
   ```

3. Authenticate Wrangler with an authorized Cloudflare account using the official Wrangler login procedure.
4. Review the deployment preview and then explicitly run `npm run deploy -- --keep-vars` from a maintainer-controlled environment. This preserves environment variables configured through the Cloudflare dashboard.
5. If a public website check is needed, configure `SCAN_ALLOWED_HOSTS` in the Worker’s production environment after deployment as a comma-separated list of exact hostnames you control. Leave it unset for a disabled website check. Never use wildcard hostnames or allow targets you do not control.
6. Verify the deployed static response headers, SPA navigation, and `/api/scan` behavior. With no allowlist configured, a valid scan submission must fail closed and make no outbound request.

The `public/_headers` file defines security headers for static assets. Worker-generated API responses set their own restrictive CSP, no-store caching, referrer, content-type, and frame headers. Static asset headers do not substitute for Worker response headers. Client source maps are not generated, and Wrangler source-map upload is disabled. Do not put credentials in public variables. No deployment or Cloudflare account configuration is performed by this repository’s CI.

### Production verification checklist

- Confirm `SCAN_ALLOWED_HOSTS` is absent or contains only exact, approved developer-owned hostnames.
- Confirm requests for non-allowlisted hosts fail before any outbound request.
- Confirm `/api/scan` permits only its documented POST contract and does not follow redirects.
- Check static responses for CSP, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, and `Permissions-Policy`.
- Check API responses separately for their Worker-set security headers and `Cache-Control: no-store`.
- Confirm the browser can assess imported diagnostic JSON without sending report contents.
- Confirm no public live-demo URL is documented until a deployment has been intentionally completed and reviewed.

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
│   ├── assessment-labels.test.ts
│   ├── assessment-labels.ts
│   ├── assessment.test.ts
│   ├── assessment.ts
│   ├── diagnostic.test.ts
│   ├── diagnostic.ts
│   ├── data/
│   ├── index.css
│   ├── main.tsx
│   └── assets/
├── worker/
│   ├── index.test.ts
│   ├── index.ts
│   ├── scan.ts
│   └── scan.test.ts
├── tools/
│   └── php-diagnostic.php
├── public/
│   └── _headers
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
| Implemented | Local PHP CLI diagnostic and client-side JSON import with strict schema validation |
| Implemented | Responsive, keyboard-accessible three-tab interface and static/API security headers |
| Implemented | Manual Wrangler deployment path with source-map upload disabled |
| Planned | Verified web-serving runtime and package diagnostics |
| Planned | Public hosted deployment |
| Planned | Broader public URL scanning and automated verification workflows |

## Current limitations

- Public checks are deliberately restricted to exact, explicitly allowlisted hostnames.
- The website checker operates on public headers only and does not verify the actual runtime or vendor packages.
- The local server diagnostic reports CLI PHP only; web-serving PHP may use a different runtime or configuration.
- Diagnostic JSON is user-provided and is not authenticated. Reports are only inspected in the local browser and are not uploaded.
- Vendor package backports are not automatically verified.
- Arbitrary public URL submissions remain disabled.
- This project does not perform vulnerability confirmation or exploit testing.
- It does not persist scan history or add user accounts.
- Website checks remain safe only for explicitly configured developer-controlled destinations; URL string validation alone is not a DNS rebinding or connection-level defense for arbitrary targets.

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
| Milestone 3 | Implemented | Read-only local CLI diagnostic and browser-only report assessment; not authenticated and not a web-runtime verification |
| Milestone 4 | Completed | Responsive accessible interface, production headers, and deployment-readiness checks; not deployed |
| Verified web-server diagnostics | Planned | Would require an independently reviewed and scope-limited design |
| Hosted public deployment | Planned | Not yet implemented |

## Contributing

Contributions are welcome when they improve the project’s quality, clarity, and security posture. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening an issue or pull request.

## License

This project is licensed under the [MIT License](./LICENSE).

## Maintainer

The repository is maintained by the GitHub owner: [@Anwar0904](https://github.com/Anwar0904).

## Security reporting

Please review [SECURITY.md](./SECURITY.md) before reporting a vulnerability.
