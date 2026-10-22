# Security Policy

This project is a security-assessment utility focused on version-evidence and allowlisted public-header checks. It is not a general-purpose website scanner or an exploit framework.

## Supported development versions

This project is currently maintained against the versions declared in the repository toolchain and the GitHub Actions workflow. Use the current Node.js LTS release for local development and validation.

## How to report vulnerabilities

If GitHub private vulnerability reporting is enabled for this repository, use the repository Security tab to report the issue privately. Do not disclose the details in a public issue.

If private reporting is not enabled, contact the repository maintainer through the GitHub profile and keep the details private until a fix is ready. Do not create a public issue for a suspected vulnerability.

## Information to include

Please provide:

- a clear description of the issue,
- affected files or code paths,
- reproduction steps or a proof of concept, if available,
- expected behavior and actual behavior,
- any relevant environment details, and
- the potential impact or risk.

## Testing boundaries

- Do not test third-party websites or production systems without explicit permission.
- Do not attempt exploit validation or remote scanning of unrelated hosts.
- Do not test public infrastructure outside the project’s own allowlisted development scenarios.
- Do not publish sensitive details before the maintainers have had a chance to assess the issue.

## Response expectations

There is no guaranteed response SLA for private reports. This project is maintained as an open-source security utility, and reports are reviewed on a best-effort basis.

We appreciate responsible disclosure and will do our best to assess and address valid issues in a careful and transparent manner.
