# AI/LLM Application Threat Model

This document maps the **AI/LLM detection pack** in `rules/llm/` to two public
frameworks:

- **[OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)**
- **[MITRE ATLAS](https://atlas.mitre.org/)** — Adversarial Threat Landscape for AI Systems

Everything here is authored from those public sources against the **synthetic,
product-agnostic** `llm_app` log schema (see [`sigma-subset.md`](./sigma-subset.md)
and `src/sigmaforge/llm_schema.py`). No real product, field, index, or customer
data is referenced.

> **Why detections on LLM gateway logs?** As organisations put LLMs behind
> internal gateways/proxies, those gateways emit structured request/response
> logs. That telemetry is exactly where prompt-injection attempts, secret
> leakage, and runaway consumption become observable — making it a natural fit
> for detection-as-code.

---

## Coverage matrix

| Rule | OWASP LLM | MITRE ATLAS | Signal |
|------|-----------|-------------|--------|
| `llm_prompt_injection_phrases` | **LLM01 – Prompt Injection** | `AML.T0051` (LLM Prompt Injection), `AML.T0051.000` (Direct), `AML.T0054` (LLM Jailbreak) | Known override/jailbreak phrases in `llm.prompt` |
| `llm_secret_in_prompt` | **LLM02 – Sensitive Information Disclosure** | `AML.T0057` (LLM Data Leakage) | API keys / cloud keys / private-key material in `llm.prompt` or `llm.completion` |
| `llm_token_cost_spike` | **LLM10 – Unbounded Consumption** | `AML.T0034` (Cost Harvesting), `AML.T0029` (Denial of AI Service) | Single request with anomalously high prompt/completion token counts |

> ATLAS technique IDs were verified against MITRE's published ATLAS data
> (`mitre-atlas/atlas-data`) rather than invented.

---

## Threat narratives

### LLM01 — Prompt Injection (`AML.T0051`, `AML.T0054`)
An adversary embeds instructions in the prompt to override the system prompt,
exfiltrate the system prompt, or jailbreak guardrails ("ignore previous
instructions", "developer mode", "do anything now"). The detection looks for a
curated set of high-signal override phrases in `llm.prompt`. **Limitations:**
phrase-matching is intentionally simple and evadable; in production this pairs
with semantic classifiers — the rule is a transparent, testable first layer.

### LLM02 — Sensitive Information Disclosure (`AML.T0057`)
Secrets are pasted into prompts (a developer asking for help with code) or
leaked back in completions. The detection uses regular expressions for
well-known **public** credential formats (AWS access key IDs, OpenAI-style
`sk-` keys, PEM private-key headers) across `llm.prompt` and `llm.completion`.
**Limitations:** regexes catch known shapes only; high-entropy/custom secrets
need a dedicated secret scanner.

### LLM10 — Unbounded Consumption (`AML.T0034`, `AML.T0029`)
Cost-harvesting / denial-of-wallet: an attacker drives expensive requests to run
up spend or degrade availability on a metered model endpoint. The detection
flags a single request whose `llm.prompt_tokens` or `llm.completion_tokens`
crosses an illustrative threshold. **Limitations:** a single-event threshold is a
floor, not a substitute for per-`user.id` rate/volume aggregation in the SIEM;
tune thresholds per environment.

---

## What this pack is *not*
- Not a guardrail or runtime filter — these are **detections** over telemetry.
- Not exhaustive of the OWASP LLM Top 10; it covers three representative,
  log-observable risks end-to-end (authored → linted → converted → fire-tested).
- Not tuned to any real product. Thresholds and phrase lists are starting points.
