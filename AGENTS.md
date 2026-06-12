# sigma-forge — Project Brief (CLAUDE.md / AGENTS.md)

> This file is the canonical brief for the project and is mirrored verbatim in
> `AGENTS.md`. It captures the mission, guardrails, stack, and definition of done
> so any agent (or human) can pick up the work with full context.

## Mission
Build "sigma-forge": a detection-as-code repo that authors Sigma rules and converts them to
Splunk SPL and Microsoft Sentinel/Defender KQL, PROVES each rule fires against synthetic JSON
logs in CI, ships a classic MITRE ATT&CK pack AND an AI/LLM-application threat pack (OWASP LLM
Top 10 + MITRE ATLAS), and optionally drafts new rules with a LOCAL LLM behind a deterministic
validator. Optimize for hiring-manager skim value: green CI, a visually polished README, an
ATT&CK heatmap.

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

## Verified stack & commands
- Python 3.11 (pysigma-backend-kusto needs pySigma >=1.0 and Python >=3.10).
- Deps: typer, rich, pysigma, pyyaml, pytest, ruff, mypy, matplotlib. openai SDK for the drafter only.
- Sigma tooling:
    - `sigma-cli` provides the `sigma` command.
    - splunk backend: `pysigma-backend-splunk` (target `-t splunk`).
    - KQL backend: `pysigma-backend-kusto` (target `-t kusto`; pipelines `microsoft_xdr` for
      Defender or `sentinel_asim` for Sentinel).
    - sysmon pipeline: `pysigma-pipeline-sysmon`.
    - In a `uv` venv, install plugin packages with `uv add <pkg>` (the bundled
      `sigma plugin install` shells out to pip, which is absent in a uv venv).
- Conversion examples:
    - `sigma convert -t splunk -p sysmon rules/classic/`
    - `sigma convert -t kusto  -p microsoft_xdr rules/classic/`

## Synthetic LLM log schema (the contract)
Fictional "LLM gateway/app" JSON event, fields:
  timestamp, user.id, app.id, llm.model, llm.prompt, llm.completion,
  llm.prompt_tokens, llm.completion_tokens, request.source_ip, tool.name, tool.target_host
Defined in `src/sigmaforge/llm_schema.py`; documented in `docs/sigma-subset.md`.

## Detection content
Classic pack — logsource `process_creation`; standard SigmaHQ field names (Image, CommandLine,
ParentImage, ...):
  - `win_encoded_powershell`     -> ATT&CK T1059.001 + T1027 (powershell -enc / FromBase64String)
  - `win_certutil_download`      -> T1105 + T1140   (certutil -urlcache / -verifyctl / -decode)
  - `win_wmic_process_create`    -> T1047           (wmic process call create)
  - `win_vssadmin_shadow_delete` -> T1490           (vssadmin delete shadows)
  - `win_lsass_comsvcs_dump`     -> T1003.001       (comsvcs.dll MiniDump of lsass)
  - `win_schtasks_persistence`   -> T1053.005       (schtasks /create persistence)
AI/LLM pack — logsource custom `llm_app`; mapped to OWASP LLM + ATLAS (IDs verified at
atlas.mitre.org / mitre-atlas/atlas-data):
  - `llm_prompt_injection_phrases`    -> OWASP LLM01, ATLAS AML.T0051 (+ .000 Direct), AML.T0054
  - `llm_secret_in_prompt`            -> OWASP LLM02, ATLAS AML.T0057
  - `llm_insecure_output_handling`    -> OWASP LLM05, ATLAS AML.T0048
  - `llm_excessive_agency_tool_abuse` -> OWASP LLM06, ATLAS AML.T0053
  - `llm_system_prompt_leak`          -> OWASP LLM07, ATLAS AML.T0069.002, AML.T0057
  - `llm_token_cost_spike`            -> OWASP LLM10, ATLAS AML.T0034, AML.T0029
Correlation pack — Sigma correlations (`event_count` / `value_count` over a timespan, grouped by
`user.id`); convert to Splunk only (the Kusto backend does not implement correlations):
  - `llm_prompt_injection_burst` -> >=3 injection attempts per user.id in 10m (LLM01, AML.T0051)
  - `llm_tool_target_fanout`     -> >=5 distinct tool.target_host per user.id in 5m (LLM06, AML.T0053)
Every rule: unique GUID id, status, level, description, author, valid logsource, attack/ATLAS tags.

## Components & Definition of Done
- `src/sigmaforge/cli.py` — typer app: convert, evaluate, coverage, draft.
- `convert.py` — SPL + KQL for every rule; golden snapshots in `tests/golden/`; `make golden`
  regenerates. DoD: `pytest tests/test_convert.py` green, no conversion errors.
- `evaluate.py` — load each rule via pySigma (`SigmaCollection.from_yaml`), then evaluate the
  PARSED detection/condition tree against JSON events. Supported subset (documented): equals,
  contains, startswith, endswith, re, null; numeric compares (gt/gte/lt/lte); lists = OR;
  field maps = AND; conditions "sel and not filt", "1 of sel_*", "all of sel_*", keywords;
  correlations (event_count / value_count + timespan, sliding windows). Raise a clear error on
  anything unsupported. DoD: every positive fixture matches, every negative does not.
- `coverage.py` — emit a MITRE ATT&CK Navigator layer (v4.x JSON) from rule tags AND render a
  static heatmap PNG to `docs/images/attack-layer.png` with matplotlib. DoD: valid layer JSON,
  real technique IDs, PNG committed.
- `pipelines/llm_splunk.yml` + `llm_kusto.yml` — custom processing pipelines mapping `llm_app`
  fields. For KQL, target a custom table `LLMAppLogs_CL`. FALLBACK: if the Kusto backend rejects
  the custom logsource, commit hand-validated golden KQL plus a documented Limitations note.
- `tests/test_lint.py` — every rule passes pySigma validation.
- `draft.py` — `sigma-forge draft "<threat sentence>"`. OpenAI-compatible endpoint via env:
  `OPENAI_BASE_URL` (default `http://localhost:1234/v1`), `OPENAI_API_KEY` optional. Pipe the
  model's YAML through lint -> convert -> evaluate; print accept/reject + errors; never write an
  invalid rule. DoD: tests MOCK the model, prove the validator accepts a good rule and rejects a
  bad one, zero network calls.

## CI (.github/workflows/ci.yml)
On push and PR, a Python 3.11 + 3.12 matrix: `uv sync --frozen` (deps incl. sigma backends) ->
ruff check + ruff format --check + mypy -> convert all rules to SPL and KQL (fail on error) ->
pytest (lint, golden conversions, fire-tests) -> rebuild the ATT&CK layer, fail if the committed
JSON is stale, and upload it as an artifact. A separate gitleaks job scans for secrets. CI,
license, and python-version badges in the README.

## Repo layout
```
.github/{workflows/ci.yml, dependabot.yml} |
docs/{threat-model.md, sigma-subset.md, attack-layer.json, images/} |
rules/{classic/,llm/,correlation/} (DRL-1.1) | pipelines/{llm_splunk.yml, llm_kusto.yml} |
sample_logs/{classic/,llm/,correlation/} (*.positive.json, *.negative.json) |
src/sigmaforge/{cli.py, convert.py, evaluate.py, coverage.py, lint.py, llm_schema.py, draft.py} |
tests/{test_lint.py, test_convert.py, test_evaluate.py, test_correlation.py, test_coverage.py,
       test_draft.py, regen_golden.py, golden/} |
CLAUDE.md AGENTS.md README.md CONTRIBUTING.md SECURITY.md LICENSE .gitignore .env.example
.gitleaks.toml .pre-commit-config.yaml Makefile pyproject.toml requirements.txt uv.lock demo.tape
```
Makefile targets: install, lint, typecheck, convert, evaluate, coverage, golden, test, draft, clean.

## Definition of Done
From a clean clone, `make test` passes with NO API keys; every rule lints, converts to SPL+KQL,
and fires correctly; the README looks polished and sells the value in one screen; the ATT&CK
heatmap renders; v0.1.0 is tagged; everything is committed (and pushed if a remote exists). The AI
pack is present even if the drafter is skipped.

## License
MIT for code; Detection Rule License (DRL-1.1) for `rules/`.
