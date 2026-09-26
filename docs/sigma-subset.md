# Evaluation contract

This document specifies what `sigma-forge check` proves about a rule, the Sigma
subset its offline evaluator supports, and the exact semantics of each
construct. The implementation is `src/sigmaforge/evaluate.py`; every rule below
is covered by `tests/test_evaluate.py` and `tests/test_correlation.py`.

## What a passing rule means

`sigma-forge check` passes a rule only when all of the following hold:

1. **Lint.** The rule parses with pySigma, carries the required metadata, its
   tags resolve against the pinned ATT&CK, ATLAS, and OWASP taxonomies, and it
   avoids constructs that do not port to every backend (see
   [Lint policy](#lint-policy)).
2. **Convert.** It compiles for every target that applies to its log family.
   The output is compared with a reviewed snapshot in `tests/golden/`.
3. **Fire-test.** Every positive fixture event fires the rule and no negative
   fixture event does. For correlations, the positive scenario triggers and the
   negative scenario does not, under both window models.

The evaluator executes the rule's **Sigma** semantics against the fixtures. It
does not execute the generated SPL or KQL: there is no offline Splunk or Kusto
engine. The conversion snapshots are the reviewable record of what each backend
emits, and the known gaps between Sigma semantics and backend behaviour are
listed under [Limitations](#limitations).

## Fixtures

Each rule `rules/<pack>/<name>.yml` has two fixture files:

```text
sample_logs/<pack>/<name>.positive.json   events the rule must fire on
sample_logs/<pack>/<name>.negative.json   events the rule must stay silent on
```

A fixture file is a non-empty JSON array of event objects (at most 5,000 events
and 5 MiB). Fields may be flat dotted keys (`{"llm.prompt": "..."}`) or nested
objects (`{"llm": {"prompt": "..."}}`); a flat key wins when both exist. For
correlations, each file is one scenario. Fixtures of `llm_app` rules must match
the [event schema](#synthetic-llm_app-event-schema): unknown fields and wrongly
typed values are errors. A fixture file without a rule fails the workspace check.

## Value matching

Matching is case-insensitive unless noted. A field that is absent or `null`
never satisfies a positive test (only `null` and `exists: false` match it). When
an event value is a list, the test passes if any element passes.

| Construct | Example | Semantics |
|---|---|---|
| plain value | `Image: 'C:\Windows\cmd.exe'` | the whole value matches; `*` and `?` are wildcards, `\*` is a literal |
| `contains` / `startswith` / `endswith` | `CommandLine\|contains: '-enc'` | substring, prefix, suffix |
| `all` | `CommandLine\|contains\|all: [a, b]` | every listed value must match (lists are otherwise OR) |
| `cased` | `CommandLine\|cased: 'Invoke'` | case-sensitive match |
| `windash` | `CommandLine\|windash\|contains: ' -enc '` | also matches `/`, en dash, em dash, and horizontal bar in place of `-` |
| `base64offset` | `CommandLine\|base64offset\|contains: 'IEX'` | any of the three Base64 alignments |
| `base64` | `CommandLine\|base64: 'x'` | pySigma encodes the value at parse time; it matches the encoded literal |
| `re` | `CommandLine\|re: 'a\d+'` | unanchored, case-sensitive search; `\d`, `\w`, `\s`, `\b` are ASCII-only, as in PCRE and RE2 |
| `re\|i`, `re\|m`, `re\|s` | `Message\|re\|i: 'x'` | ignore case, multi-line anchors, dot matches newline |
| number | `EventID: 1` | numeric equality; numeric strings such as `"1"` are converted, booleans are not numbers |
| `gt` / `gte` / `lt` / `lte` | `llm.prompt_tokens\|gte: 8000` | numeric comparison; non-numeric values do not match |
| boolean | `Elevated: true` | a JSON boolean, or the string `true`/`false` in any case |
| `null` | `ParentImage: null` | the field is absent or `null` |
| `exists` | `User\|exists: true` | the field holds a value other than `null`, `""`, `[]`, or `{}` |
| `cidr` | `SourceIp\|cidr: 10.0.0.0/8` | IPv4 or IPv6 network membership; values that are not IP addresses do not match |

**Keywords** (a detection that is a plain list of values) are a full-text
search: a keyword matches when it occurs anywhere in any scalar value of the
event. The evaluator supports them, but the [lint policy](#lint-policy) rejects
them because the Kusto backend compiles them to invalid KQL.

## Conditions

pySigma resolves the condition grammar; the evaluator walks the resulting tree:
`and`, `or`, `not`, parentheses, `1 of sel_*`, `all of sel_*`, `1 of them`, and
`all of them`. Values in a list are OR-linked and fields in a map are
AND-linked. A rule with several conditions fires when any condition holds,
matching backends that emit one query per condition.

## Correlations

`event_count` and `value_count` correlations are supported:

- Events are matched against the base rules the correlation references (other
  rules in the file do not count), then grouped by the `group-by` fields.
- Like Splunk's `stats ... by`, events that lack a group-by value are dropped.
  Like `dc()`, `value_count` ignores events whose counted field is null.
  Group-by and counted values compare as strings, as they do in Splunk, so
  `1` and `"1"` are the same user; a list or object value is an error.
- Events need a `timestamp` in ISO-8601; a timestamp without a timezone is
  read as UTC. A missing or unparseable timestamp is an error.
- The condition operators are `gt`, `gte`, `lt`, `lte`, `eq`, and `neq`.

**Window models.** A `timespan` can be applied in two ways, and SIEMs differ:

| Model | Windows | Used by |
|---|---|---|
| sliding | `[t, t + timespan)` starting at each event | the intent of most correlation rules |
| tumbling | fixed `[k * timespan, (k + 1) * timespan)` buckets aligned to the Unix epoch | the SPL that pySigma emits: `bin _time span=<timespan>` |

The two disagree when a burst straddles a bucket boundary: 14:09, 14:10, and
14:11 fit one sliding 10-minute window but fall into two fixed buckets. The
fire-test therefore evaluates every scenario under both models and fails a
scenario whose verdict depends on the model. A passing correlation fixture
proves the behaviour whichever way the SIEM buckets time.

Sliding windows are evaluated in linear time after sorting. For `gt` and `gte`
(the operators used in practice) the result is exact; the other operators are
evaluated over the windows that start at each event. A group may hold at most
5,000 matching events.

## Refused constructs

The evaluator raises `UnsupportedFeatureError`, and the fire-test fails, for:
`fieldref`, placeholders (`|expand` with `%name%`), correlation types other than
`event_count` and `value_count` (`temporal`, `temporal_ordered`, `value_sum`,
`value_avg`, `value_percentile`, `value_median`), correlation field `aliases`,
and correlations of correlations. The check happens when the rule is compiled,
so an unsupported construct in a branch that the fixtures never reach still
fails. A regular expression that exceeds a 0.25-second budget on a fixture
value is killed and reported instead of hanging the gate.

## Lint policy

Beyond pySigma's core validators, lint enforces:

- **Metadata**: `id` (a UUID), `title`, `status`, `level`, `description`,
  `author`, `date`, and at least one tag on every rule; a `logsource` with a
  `product` and a `category` or `service`, and at least one public `https://`
  reference on every plain rule.
- **Shape**: a file holds exactly one rule, or one correlation plus exactly
  the base rules it references.
- **Taxonomy**: `attack.*` tags name a current ATT&CK Enterprise v19.2
  technique or tactic (group and software IDs are checked by format only), and a
  rule's tactic tags must belong to its tagged techniques; `atlas.*` tags name an
  ATLAS 2026.09 technique or tactic; `owasp.*` tags name an entry of the OWASP
  Top 10 for LLM Applications 2025. Other namespaces must be ones Sigma defines
  (`car`, `cve`, `d3fend`, `detection`, `stp`, `tlp`).
- **Portability**: no keyword detections, and no regex construct that RE2
  (and therefore KQL) rejects: lookarounds, backreferences, atomic groups,
  possessive quantifiers, and conditionals.
- **Schema**: `llm_app` rules and their correlations reference only fields of
  the synthetic schema, which catches typos that would compile but never match.
- **Uniqueness**: ids, names, and titles are unique across the rule set.

The taxonomy snapshots are pinned in `src/sigmaforge/data/` and refreshed
deliberately with `make taxonomy`, so lint results never depend on the network.

## Synthetic `llm_app` event schema

A fictional, product-agnostic LLM gateway event, defined in
`src/sigmaforge/llm_schema.py`:

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | ISO-8601 event time |
| `user.id` | string | pseudonymous caller identity |
| `app.id` | string | calling application or tenant |
| `llm.model` | string | model the request targeted |
| `llm.prompt` | string | prompt text sent to the model |
| `llm.completion` | string | completion text returned by the model |
| `llm.prompt_tokens` | integer | prompt token count |
| `llm.completion_tokens` | integer | completion token count |
| `request.source_ip` | string | source IP address of the request |
| `tool.name` | string | tool or function the agent invoked |
| `tool.target_host` | string | host the tool call targeted |

The conversion pipelines map these fields to backend names:

| Target | Pipeline | Mapping |
|---|---|---|
| Splunk | `src/sigmaforge/pipelines/llm_splunk.yml` | scopes to `sourcetype="llm:gateway"`; `llm.prompt` becomes `llm_prompt`, `request.source_ip` becomes `src_ip`, and so on |
| Sentinel | `src/sigmaforge/pipelines/llm_sentinel.yml` | queries the custom Log Analytics table `LLMAppLogs_CL`; `llm.prompt` becomes `PromptText`, and so on |

The sourcetype, table, and column names are illustrative conventions for the
synthetic schema, not names defined by Splunk or Microsoft. Map them to your
own ingestion before deploying.

## Limitations

- **Sigma semantics, not backend execution.** Backends differ from Sigma in
  details the evaluator cannot model. Splunk matches bare keywords against
  indexed tokens, so a keyword can miss text inside a longer word (one reason
  lint rejects keywords); KQL `contains` ignores case while `matches regex` does
  not; and the SPL assumes the mapped fields are extracted at search time.
- **Correlations compile to Splunk only.** pySigma's Kusto backend does not
  implement correlation rules, so there is no KQL output for them.
- **Sentinel ASIM and `OriginalFileName`.** The Sentinel ASIM pipeline in
  pySigma-backend-kusto 1.0.1 maps `OriginalFileName` to a column that
  `imProcessCreate` does not have, so the Windows rules match on `Image`
  (process path) only.
- **Detections are starting points.** Phrase lists, regular expressions, and
  thresholds are illustrative, drawn from public sources; tune them to your
  environment.
