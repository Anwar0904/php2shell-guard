# Contributing

We welcome contributions that improve the security quality, reliability, and clarity of the project.

Please keep changes focused and aligned with the current milestone scope. Do not add unrelated scanning features, databases, authentication, or deployment flow to this repository without a separate design discussion.

## Development setup

1. Install dependencies with `npm install`.
2. Use the project scripts from `package.json` for local validation.
3. Run the test suite before opening a pull request.

## Branching and pull requests

- Create a branch that describes the change clearly.
- Keep pull requests small and reviewable.
- Reference the issue or milestone being addressed when relevant.
- Include a concise summary of what changed and what was verified.

## Coding expectations

- Preserve the existing architecture and security boundaries.
- Keep TypeScript types explicit and maintainable.
- Add or update tests when changing behavior.
- Do not weaken validation or safety checks to satisfy tests.
- Do not add runtime dependencies unless the change requires them and the maintainers approve the tradeoff.

## Testing requirements

Before opening a pull request, run:

```sh
npm test
npm run build
npm run lint
git diff --check
```

## Reporting bugs

- Use the GitHub issue tracker for reproducible bugs.
- Provide clear reproduction steps, environment details, and any relevant logs.
- For security-sensitive issues, follow the process in [SECURITY.md](./SECURITY.md) and keep the report private.

## Suggesting features

Open an issue with the problem statement, a proposed solution, and any constraints or alternatives considered. Keep the discussion focused on the specific capability being proposed.

## Security boundaries for testing

- Do not test third-party websites or domains without explicit permission.
- Do not attempt exploit validation or vulnerability confirmation against live public targets.
- Do not add or rely on external scanning or exploit tooling in this repository.
- Keep any local validation within the project’s mocked test and allowlisted-host workflows.

Thank you for helping keep this project credible, safe, and maintainable.
