# AI/LLM application threat model

The AI/LLM pack (`rules/llm/`, `rules/correlation/`) detects attacks on
applications that reach a language model through a gateway: a proxy that logs
each request, its completion, token counts, and any tool calls an agent makes.
The detections map to two public frameworks:

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for
  AI Systems), release 2026.09

Every rule is written against the synthetic, product-agnostic `llm_app` event
schema described in [`sigma-subset.md`](sigma-subset.md#synthetic-llm_app-event-schema).
No real product, field, index, or customer data is referenced. ATLAS IDs are
validated against the pinned ATLAS release in `src/sigmaforge/data/atlas.json`.

## Why gateway telemetry

Prompt-level attacks leave no host artefacts: an injection, a leaked secret, or
a runaway completion is only visible in the request and response the gateway
records. Treating that log as a detection source brings LLM applications into
the same author, test, and deploy loop as endpoint detections.

## Coverage

| Rule | OWASP LLM 2025 | MITRE ATLAS | Signal |
|---|---|---|---|
| `llm_prompt_injection_phrases` | LLM01 Prompt Injection | AML.T0051.000 LLM Prompt Injection: Direct; AML.T0054 LLM Jailbreak | override or jailbreak phrase in `llm.prompt` |
| `llm_secret_in_prompt` | LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | AWS access key ID, `sk-` API key, or PEM private-key header in the prompt or completion |
| `llm_insecure_output_handling` | LLM05 Improper Output Handling | AML.T0077 LLM Response Rendering | script or iframe tags, `javascript:` URIs, inline event handlers, destructive SQL, or a Markdown image whose URL carries a query string |
| `llm_excessive_agency_tool_abuse` | LLM06 Excessive Agency | AML.T0053 AI Agent Tool Invocation | shell, file-deletion, email, or HTTP tool aimed at a loopback, private, internal, or cloud-metadata host |
| `llm_system_prompt_leak` | LLM07 System Prompt Leakage | AML.T0056 Extract LLM System Prompt | completion echoes system-prompt or instruction markers |
| `llm_token_cost_spike` | LLM10 Unbounded Consumption | AML.T0034.001 Cost Harvesting: Resource-Intensive Queries; AML.T0029 Denial of AI Service | one request with at least 8,000 prompt or completion tokens |
| `llm_prompt_injection_burst` (correlation) | LLM01 | AML.T0051.000; AML.T0054 | at least 3 injection attempts by one `user.id` within 10 minutes |
| `llm_tool_target_fanout` (correlation) | LLM06 | AML.T0053 | request-style tool calls by one `user.id` to at least 5 distinct hosts within 5 minutes |

Not covered: LLM03 Supply Chain, LLM04 Data and Model Poisoning, and LLM08
Vector and Embedding Weaknesses leave their evidence in build, training-data,
and retrieval-store telemetry rather than in per-request gateway logs. LLM09
Misinformation does appear in completions, but it cannot be recognised by
pattern matching; it needs evaluation pipelines.

## Threats and detections

### LLM01 Prompt Injection (AML.T0051.000, AML.T0054)

An attacker writes instructions into the prompt to override the system prompt,
disable guardrails, or extract hidden context ("ignore previous instructions",
"developer mode", "do anything now"). The single-event rule matches a curated
list of override phrases. The burst correlation raises the same signal to high
confidence when one user keeps iterating on payloads; its base rule uses the
standalone rule's phrase list, and a test keeps the two identical.

*Limits:* phrase matching is transparent, testable, and easy to evade with
paraphrase, encoding, or other languages. Pair it with a semantic classifier;
this rule is the auditable first layer.

### LLM02 Sensitive Information Disclosure (AML.T0057)

Secrets reach the model when users paste them into prompts, and leave it when a
completion repeats them. The rule applies one regular expression to both
fields: AWS access key IDs, `sk-` style API keys (including project and
service-account keys), and PEM private-key headers. Word boundaries stop `sk-`
from matching inside ordinary words such as "risk-". The expression uses only
RE2 syntax so that it compiles for KQL.

*Limits:* only known key shapes are caught; high-entropy or custom secrets need
a dedicated secret scanner in the gateway.

### LLM05 Improper Output Handling (AML.T0077)

A completion that a client renders or executes without sanitising can carry
active content: script and iframe tags, `javascript:` URIs, inline event
handlers, or SQL. A Markdown image whose URL carries a query string is the
common exfiltration pattern: when the client fetches the image, the
conversation data encoded in the URL goes to the attacker's server.

*Limits:* the real fix is output encoding in the consuming application. Coding
assistants legitimately return HTML and SQL; scope the rule by `app.id`.

### LLM06 Excessive Agency (AML.T0053)

An agent with broad tool permissions can be steered into running commands,
deleting files, sending email, or making HTTP requests against internal
systems. The single-event rule flags a high-impact tool aimed at a loopback,
RFC 1918, `.internal`/`.local`, or cloud instance-metadata host
(`169.254.169.254`). The fan-out correlation flags an agent that reaches many
distinct hosts in a short window, which looks like scanning driven through the
agent.

*Limits:* allowlist sanctioned automations, and tune the tool and host lists to
the agent's real permissions.

### LLM07 System Prompt Leakage (AML.T0056)

A leaked system prompt exposes business logic, guardrail wording, and
sometimes credentials, and it is often the first payoff of a successful
injection. The rule flags completions that echo instruction markers such as
"BEGIN SYSTEM PROMPT" or "my instructions are".

*Limits:* phrase-based; it pairs well with the injection rules above.

### LLM10 Unbounded Consumption (AML.T0034.001, AML.T0029)

Resource-intensive requests drive up spend on a metered model (denial of
wallet) or degrade the service for other users. The rule flags a single request
with at least 8,000 prompt or completion tokens.

*Limits:* the threshold is illustrative; set it from the application's
baseline. Sustained abuse by many small requests needs a rate-based
correlation.

## Scope

- These are detections over telemetry, not a runtime guardrail or filter.
- They cover six OWASP LLM risks and two correlations, each authored, linted,
  compiled to SPL and KQL, and fire-tested against synthetic events.
- Thresholds, phrase lists, and host patterns are starting points, drawn from
  public sources; tune them before production use.
