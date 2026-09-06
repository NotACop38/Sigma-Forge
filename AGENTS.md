# AGENTS.md - Sigma-Forge

This file is the operating contract for coding agents. Sigma-Forge authors defensive Sigma detections, converts them to SPL and KQL, and checks them against synthetic fixtures. Start with the user's task and `git status --short --branch`; preserve unrelated work.

## Hard guardrails (never violate)
- Defensive/educational only. No offensive tooling or working exploit payloads.
- Employer-safe: author everything from PUBLIC sources (MITRE ATT&CK, OWASP Top 10 for LLM
  Applications, MITRE ATLAS). No real detections/configs/logs, no employer/customer names, no
  internal field/index names. All sample logs are SYNTHETIC and product-agnostic.
- No secrets in the repo; add a gitleaks pre-commit hook and a CI secret scan; ship .env.example.
- No live LLM/API calls in CI or tests — mock them. The offline core must run with ZERO API keys.
- The optional drafter NEVER writes a rule that hasn't passed schema-lint -> conversion ->
  fire-test; default it to a LOCAL endpoint.
- Be transparent about tooling limits in the docs (especially KQL for the custom LLM logsource).

## Scope and context

- Complete the authorized task. A maintenance, review, or documentation request does not require adding detection packs, polishing the whole product, or creating a release.
- Read only the supporting sections needed for the task, and reuse context already read unless it has changed. `CLAUDE.md` is a compatibility pointer to this operating contract.
- Use `docs/sigma-subset.md` for the supported rule and evaluation contract, `docs/threat-model.md` for defensive scope, and `src/sigmaforge/llm_schema.py` for the synthetic event schema. Check current rules, fixtures, and tests when changing behavior rather than relying on a duplicated inventory.
- `pyproject.toml` and `uv.lock` define dependencies; `Makefile` defines local commands; `.github/workflows/ci.yml` defines CI. Use `uv` to manage Sigma plugin packages: `sigma plugin install` assumes pip is available in the environment.
- Make routine, reversible choices within scope. Ask only when a missing decision or authorization materially changes the result and cannot be inferred. Do not ask again for approval already given.

## Verification and delivery

- Use targeted checks during work, then `make test` for the completed change with no API keys. Every affected rule must lint, convert for its supported backends, and match positive fixtures while rejecting negative fixtures. Keep the documented Kusto correlation limitation explicit.
- Preserve the workflow's conversion, Navigator-layer freshness, lockfile export, and secret-scan checks. Run the relevant checks when their inputs change; do not regenerate goldens or artifacts merely to hide a failing comparison.
- Reuse passing results while the checked revision and inputs remain unchanged. Rerun affected checks after further changes and report failures or checks that could not run accurately.
- Review the diff for secrets, private/local traces, real-world data, and unsupported claims before publishing. Keep examples synthetic and preserve the secret-scan allowlist boundaries.
- Commit only the intended changes and follow the user's delivery instructions. Create tags or releases only when requested.

## License

MIT for code; Detection Rule License (DRL-1.1) for `rules/`.
