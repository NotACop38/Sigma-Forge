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
| `llm_insecure_output_handling` | **LLM05 – Improper Output Handling** | `AML.T0048` (External Harms) | Active content (`<script>`, `javascript:`, SQL) in `llm.completion` |
| `llm_excessive_agency_tool_abuse` | **LLM06 – Excessive Agency** | `AML.T0053` (AI Agent Tool Invocation) | High-impact `tool.name` against an internal / metadata `tool.target_host` |
| `llm_system_prompt_leak` | **LLM07 – System Prompt Leakage** | `AML.T0069.002` (System Prompt), `AML.T0057` (LLM Data Leakage) | Completion echoes system-prompt / instruction markers |
| `llm_token_cost_spike` | **LLM10 – Unbounded Consumption** | `AML.T0034` (Cost Harvesting), `AML.T0029` (Denial of AI Service) | Single request with anomalously high prompt/completion token counts |

**Correlation rules** (multi-event aggregation; see [`sigma-subset.md`](./sigma-subset.md#correlation-rules)):

| Rule | OWASP LLM | MITRE ATLAS | Signal |
|------|-----------|-------------|--------|
| `llm_prompt_injection_burst` | **LLM01** | `AML.T0051` | `event_count` ≥ 3 injection attempts per `user.id` within 10m |
| `llm_tool_target_fanout` | **LLM06** | `AML.T0053` | `value_count` ≥ 5 distinct `tool.target_host` per `user.id` within 5m |

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

### LLM05 — Improper Output Handling (`AML.T0048`)
The model returns active content — `<script>`/`<iframe>` tags, `javascript:`
URIs, event handlers, or SQL statements — that a downstream consumer might render
or execute without sanitisation, leading to XSS/SSRF/injection. The detection
flags such content in `llm.completion`. **Limitations:** the real fix is
consumer-side output encoding; this catches the most obvious shapes and is
noisy for code assistants (tune per app).

### LLM06 — Excessive Agency (`AML.T0053`)
An over-permissioned agent invokes a high-impact tool (shell/command, file
deletion, email, HTTP) against an internal or cloud-metadata host. The detection
combines `tool.name` with a `tool.target_host` regex (`*.internal`, RFC1918,
`169.254.169.254`). **Limitations:** allowlist sanctioned automations; tune the
host/tool lists to your environment.

### LLM07 — System Prompt Leakage (`AML.T0069.002`, `AML.T0057`)
The completion discloses the model's own system prompt / instructions (often the
goal of a successful injection). The detection flags instruction markers in
`llm.completion`. **Limitations:** phrase-based; pairs well with the injection
rules and the burst correlation below.

### LLM10 — Unbounded Consumption (`AML.T0034`, `AML.T0029`)
Cost-harvesting / denial-of-wallet: an attacker drives expensive requests to run
up spend or degrade availability on a metered model endpoint. The detection
flags a single request whose `llm.prompt_tokens` or `llm.completion_tokens`
crosses an illustrative threshold. **Limitations:** a single-event threshold is a
floor — the correlation rules below add the per-`user.id` aggregation; tune
thresholds per environment.

### Correlations — bursts & fan-out (`AML.T0051`, `AML.T0053`)
Single events are noisy; correlations raise confidence. `llm_prompt_injection_burst`
fires when one `user.id` makes ≥3 injection attempts within 10 minutes, and
`llm_tool_target_fanout` fires when one `user.id` drives an agent across ≥5
distinct tool target hosts within 5 minutes (scanning-like behaviour). These are
fire-tested over multi-event scenarios with `timespan` windows.

---

## What this pack is *not*
- Not a guardrail or runtime filter — these are **detections** over telemetry.
- Not exhaustive of the OWASP LLM Top 10; it covers six representative,
  log-observable risks plus two correlations, end-to-end (authored → linted →
  converted → fire-tested).
- Not tuned to any real product. Thresholds and phrase lists are starting points.
