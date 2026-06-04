# Security Policy

sigma-forge is a **defensive, educational** detection-as-code project. It contains
no offensive tooling and no working exploit payloads, and every sample log is
synthetic and product-agnostic. Still, we take the security of the code and its
supply chain seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Instead, report privately via GitHub's
[**Security Advisories**](https://github.com/NotACop38/Sigma-Forge/security/advisories/new)
("Report a vulnerability"). This keeps the details private until a fix is
available. Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal rule, log fixture, or command is ideal), and
- any suggested remediation.

We aim to acknowledge a report within a few days and to keep you updated through
to resolution. Coordinated disclosure is appreciated.

## Scope

In scope:

- The Python package under `src/sigmaforge/` (CLI, converters, evaluator, drafter).
- CI/CD workflows under `.github/workflows/`.
- Supply-chain concerns (dependencies, pinned actions, lockfile integrity).

Out of scope (by design — see [`CLAUDE.md`](CLAUDE.md) guardrails):

- The *detection logic* of individual rules (phrase lists, regexes, thresholds)
  is illustrative and meant to be tuned per environment — tuning gaps are not
  security vulnerabilities.
- The optional rule drafter is **local-first** and makes **no network calls in
  CI or tests**; the offline core runs with zero API keys.

## Hardening already in place

- **No secrets in the repo.** A [gitleaks](https://github.com/gitleaks/gitleaks)
  pre-commit hook and a CI secret-scan job guard every commit and the working
  tree. The only allowlisted strings are clearly-labelled, non-functional
  synthetic fixtures (see `.gitleaks.toml`).
- **Least-privilege CI.** Workflows declare `permissions: contents: read` and
  pin actions to released versions.
- **Deterministic, offline-by-default core.** Conversion, evaluation, linting,
  and tests require no API keys and no outbound network access.
- **Dependency updates** are proposed automatically via Dependabot
  (`.github/dependabot.yml`) for both Python packages and GitHub Actions.
