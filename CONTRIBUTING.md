# Contributing to sigma-forge

Thanks for your interest! sigma-forge is a **defensive, educational**
detection-as-code project. Contributions of new rules, backends, docs, and
fixes are welcome.

## Ground rules

Read [`CLAUDE.md`](CLAUDE.md) first — it is the canonical project brief and lists
the hard guardrails. The most important ones:

- **Defensive/educational only.** No offensive tooling or working exploit
  payloads.
- **Public sources only.** Author detections from public references (MITRE
  ATT&CK, OWASP Top 10 for LLM Applications, MITRE ATLAS). No proprietary
  detections, configs, logs, or internal field/index names.
- **Synthetic logs only.** All sample logs are fictional and product-agnostic.
- **No secrets.** The gitleaks hook will block credentials; never commit a real
  `.env`.

## Getting set up

```bash
git clone https://github.com/NotACop38/Sigma-Forge.git && cd Sigma-Forge
uv sync                       # creates the venv + installs sigma backends/pipelines
pre-commit install            # gitleaks + ruff hooks (optional but recommended)
make test                     # ruff + pytest — needs NO API keys
```

## Adding a rule

1. Add the Sigma YAML under `rules/classic/`, `rules/llm/`, or
   `rules/correlation/`. Every rule needs a unique UUID `id`, `status`, `level`,
   `description`, `author`, a valid `logsource`, and ATT&CK/ATLAS/OWASP tags.
2. Add fire-test fixtures: `sample_logs/<pack>/<rule>.positive.json` (must match)
   and `<rule>.negative.json` (must not).
3. Regenerate golden conversions: `make golden`.
4. Run the full suite:

   ```bash
   make lint        # ruff
   make typecheck   # mypy
   uv run sigma-forge convert  --all
   uv run sigma-forge evaluate --all
   make test
   ```

All of `ruff`, `mypy`, rule conversion (SPL + KQL), and the fire-tests must be
green — CI enforces the same gates across Python 3.11 and 3.12.

## Pull requests

- Keep changes focused and described clearly.
- Update the docs (`README.md`, `docs/`) when behaviour changes.
- The evaluator supports a documented subset of Sigma — if a rule uses a
  construct outside it, the evaluator raises a clear error by design rather than
  guessing. See [`docs/sigma-subset.md`](docs/sigma-subset.md).

## License of contributions

By contributing you agree that your code is licensed under [MIT](LICENSE) and
your detection content under the
[Detection Rule License (DRL) 1.1](rules/LICENSE), matching the rest of the repo.
