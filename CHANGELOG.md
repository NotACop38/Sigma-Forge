# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-26

A full audit and rework. Rule semantics, taxonomy mappings, and the CLI changed;
see the migration notes below.

### Added

- `sigma-forge check`: one gate that lints, converts, and fire-tests every rule,
  checks workspace-wide invariants (unique ids, names, and titles; no orphaned
  fixtures), prints a per-rule matrix, and supports `--json`.
- Pinned, offline taxonomy snapshots of MITRE ATT&CK Enterprise v19.2 and MITRE
  ATLAS 2026.09 (`src/sigmaforge/data/`, refreshed by `scripts/update_taxonomy.py`).
  Lint now rejects unknown or deprecated techniques, tactic tags that do not
  belong to a tagged technique, unknown ATLAS IDs, and unknown OWASP LLM entries.
- Lint policy checks: required metadata, a public `https://` reference, at least
  one tag, one detection per file, RE2-compatible regular expressions (KQL uses
  RE2), no keyword detections (they compile to invalid KQL), and `llm_app` rules
  restricted to the synthetic schema's fields.
- Evaluator support for `|re|i`/`|re|m`/`|re|s` flags, `|cased`, `|exists`,
  `|cidr`, booleans, `|windash` and `|base64offset` expansions, and rules with
  several conditions. Unsupported constructs now fail when the rule is compiled,
  even in branches that evaluation would never reach.
- Correlation fire-tests run under both sliding windows and the fixed buckets
  the generated SPL uses; a scenario must give the same verdict under both.
- Fixture validation: files must be non-empty JSON arrays of objects, and
  `llm_app` fixtures must match the event schema (field names and types).
- A deterministic SVG coverage card (ATT&CK, ATLAS, OWASP LLM Top 10) and
  `sigma-forge coverage --check` to detect stale committed artifacts.
- Drafter: the model must return fixtures along with the rule; drafts go through
  the same gate as committed rules plus an empty-event check; validation errors
  are fed back for up to `--attempts` repairs; `--write` places the rule and its
  fixtures in the workspace and never overwrites files.
- Wheel smoke test in CI, Python 3.13 in the CI matrix, strict mypy over the
  package, tests, and scripts, and a 90% branch-coverage floor.

### Changed

- ATT&CK tags follow v19: `attack.defense-evasion` became `attack.stealth`, and
  encoded PowerShell maps to T1027.010 (Command Obfuscation).
- LLM rules map to more precise ATLAS techniques (AML.T0051.000, AML.T0056,
  AML.T0077, AML.T0034.001) and no longer carry enterprise ATT&CK tactic tags.
- Conversion targets are named after products: `splunk`, `defender` (Defender
  XDR), and `sentinel`. For `llm_app` rules, `sentinel` targets the custom
  `LLMAppLogs_CL` table (this was the `kusto` target).
- Splunk queries for `llm_app` rules are scoped to `sourcetype="llm:gateway"`,
  which also fixes regex-only rules that compiled to a query starting with `| rex`.
- Keywords are matched as a full-text search (substring of any value), like the
  backends, instead of as an exact value match.
- Correlations drop events that lack a group-by value and ignore null values in
  `value_count`, as Splunk's `stats ... by` and `dc()` do; timestamps without a
  timezone are read as UTC, and missing or invalid timestamps are errors.
- The drafter reads `SIGMA_FORGE_LLM_BASE_URL`, `SIGMA_FORGE_LLM_MODEL`, and
  `SIGMA_FORGE_LLM_API_KEY` instead of the global `OPENAI_*` variables, refuses
  non-loopback endpoints unless `--allow-remote` is given, and bypasses proxies
  for loopback traffic.
- Processing pipelines ship inside the package, so installed wheels work outside
  a source checkout; commands take `--root` or discover the workspace.
- Rule improvements: encoded PowerShell covers every `-EncodedCommand`
  abbreviation and dash variant; VSSAdmin covers `resize shadowstorage`; the
  secret regex matches project-scoped `sk-` keys without firing inside words
  like "risk-"; output handling flags Markdown-image exfiltration URLs; agent
  tool abuse covers loopback targets; the injection-burst base rule now uses the
  standalone rule's phrase list.

### Removed

- The `win_certutil_download` rule. Its positive fixture was removed from the
  repository several times, and a rule without a positive fixture is unproven.
- `sigma-forge evaluate` (use `sigma-forge check`), `coverage --site`, and the
  `--check` flag of `convert` (conversion failures now always exit 1).
- Runtime dependencies on `openai`, `matplotlib`, and `sigma-cli`; the demo GIF,
  which showed commands that no longer exist.

### Fixed

- Lint enabled pySigma's mutually exclusive TLP v1 and v2 validators together,
  so a rule could not carry `tlp.clear` or `tlp.white`.
- Duplicate ids, names, or titles across rule files were not detected.

## [0.1.0] - 2026-06-03

Initial release: Sigma rules for Windows process creation and a synthetic LLM
gateway, conversion to Splunk SPL and Microsoft KQL, an offline fire-test
evaluator, correlation rules, an ATT&CK Navigator layer, and a local-first
rule drafter.
