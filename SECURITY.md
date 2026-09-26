# Security policy

sigma-forge is a defensive, educational detection-as-code project. It contains
no offensive tooling or working exploit payloads, and every fixture event is
synthetic. The code and its supply chain are still treated as security
sensitive: the gate evaluates rule-controlled regular expressions, and the
optional drafter processes untrusted model output.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately
through [GitHub Security Advisories](https://github.com/NotACop38/Sigma-Forge/security/advisories/new)
("Report a vulnerability") and include:

- a description of the issue and its impact,
- steps to reproduce (a minimal rule, fixture, or command is ideal), and
- a suggested fix, if you have one.

Reports are acknowledged within a few days, and you will be kept informed until
the issue is resolved. Coordinated disclosure is appreciated.

## Scope

In scope:

- the Python package in `src/sigmaforge/` (CLI, converter, evaluator, gate,
  drafter) and the maintainer scripts in `scripts/`,
- the CI workflow in `.github/workflows/`,
- supply-chain issues: dependencies, pinned actions, and lockfile integrity.

Out of scope:

- detection quality. Phrase lists, regular expressions, and thresholds are
  illustrative and meant to be tuned; a missed attack or a false positive is a
  rule improvement, not a vulnerability.

## Safeguards

- **No secrets in the repository.** A gitleaks pre-commit hook and a CI job scan
  the full git history. The allowlist covers only three exact, fake fixture
  lines (`.gitleaks.toml`), and a CI canary plants a credential in that fixture
  file on every run to prove the allowlist cannot hide anything else.
- **Offline by default.** Lint, conversion, fire-tests, coverage, and the test
  suite need no network access and no API keys. The taxonomies are pinned
  snapshots, and the test suite fails any connection to a non-loopback address.
- **Bounded evaluation.** Rule regular expressions run in a separate process
  with a 0.25-second budget, fixture files are capped in size and event count,
  and correlation groups are capped, so a hostile rule or fixture cannot hang
  the gate.
- **Local-first drafter.** The drafter sends the threat description only to a
  loopback endpoint unless `--allow-remote` is passed, reads its own
  `SIGMA_FORGE_LLM_*` variables rather than inheriting global `OPENAI_*`
  settings, bypasses proxies for loopback traffic, and treats model output as
  untrusted: nothing is written unless the draft passes the full gate, file
  names are validated, and existing files are never overwritten.
- **Least-privilege CI.** Workflows run with `contents: read`, pin every action
  to a commit SHA, and verify the gitleaks binary against a pinned SHA-256
  checksum. Dependabot proposes updates for Python packages, actions, and
  pre-commit hooks.
