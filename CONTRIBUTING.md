# Contributing to sigma-forge

sigma-forge is a defensive, educational detection-as-code project. New rules,
backend improvements, fixes, and documentation are welcome.

## Ground rules

- **Defensive only.** No offensive tooling and no working exploit payloads.
  Fixtures describe what an attack looks like in a log; they are not tools.
- **Public sources only.** Base detections on public references (MITRE ATT&CK,
  MITRE ATLAS, the OWASP Top 10 for LLM Applications) and cite them in
  `references`. Never contribute proprietary detections, configurations, logs,
  or internal field and index names.
- **Synthetic data only.** Fixture events are fictional and product-agnostic:
  use reserved `example` domains, RFC 5737 documentation ranges for public
  addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and benign
  payloads. Encoded commands should decode to something harmless.
- **No secrets.** The gitleaks hook and CI job block credentials. The only
  exceptions are the exact, fake, allowlisted lines in
  `sample_logs/llm/llm_secret_in_prompt.positive.json`; see `.gitleaks.toml`.

## Setup

```bash
git clone https://github.com/NotACop38/Sigma-Forge.git && cd Sigma-Forge
make install                  # uv sync: virtualenv with runtime and dev dependencies
uv run pre-commit install     # optional: gitleaks and ruff before every commit
make test                     # every CI gate; no network access or API keys needed
```

## Adding a rule

1. Write the rule as `rules/<pack>/<name>.yml`, where the pack is `classic`
   (Windows, `win_` prefix), `llm` (LLM gateway, `llm_` prefix), or
   `correlation`. Give it a fresh UUID `id`, a unique `title`, `status`,
   `level`, `description`, `author`, `date`, `references`, `falsepositives`,
   and tags:
   - Windows: at least one ATT&CK v19 technique and its tactic, for example
     `attack.execution` and `attack.t1059.001`.
   - LLM gateway: an OWASP LLM tag (`owasp.llm01`) and ATLAS techniques
     (`atlas.t0051.000`). Use only fields from `src/sigmaforge/llm_schema.py`.
2. Add fixtures next to it: `sample_logs/<pack>/<name>.positive.json` with
   events the rule must fire on, and `<name>.negative.json` with realistic near
   misses it must ignore. Cover every branch of the condition with a positive.
3. Run `uv run sigma-forge check rules/<pack>/<name>.yml` until it passes.
4. Snapshot the conversions with `make golden` and review the new files in
   `tests/golden/`.
5. Refresh the coverage artifacts with `make docs` (the layer, the coverage
   card, and the README's gate output).
6. Run `make test`.

`sigma-forge draft` can produce a first version of steps 1 and 2 with a local
model; the draft still needs human review before it is committed.

## Pull requests

- Keep changes focused and describe what changed and why.
- Update `README.md`, `docs/`, and `CHANGELOG.md` when behaviour changes.
- Golden snapshots record what each backend emits. Regenerate them only for an
  intended conversion change, never to make a failing comparison pass.
- The evaluator implements a documented Sigma subset
  ([`docs/sigma-subset.md`](docs/sigma-subset.md)). A rule that needs a construct
  outside it fails the gate on purpose; extend the evaluator, with tests, rather
  than weakening the gate.

## Maintenance

- `make taxonomy` refreshes the pinned ATT&CK and ATLAS snapshots from MITRE.
  Review the data diff, then run `make test`: a renamed tactic or revoked
  technique surfaces as lint failures in the rules that use it.
- `make requirements` re-exports `requirements.txt` after dependency changes.

## Licensing of contributions

By contributing you agree that code is licensed under [MIT](LICENSE) and
detection content under the [Detection Rule License 1.1](rules/LICENSE).
