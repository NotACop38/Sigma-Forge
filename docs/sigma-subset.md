# Supported Sigma Subset & Synthetic LLM Schema

sigma-forge's evaluator (`src/sigmaforge/evaluate.py`) **fire-tests** rules by
evaluating the *parsed pySigma detection tree* against JSON events. It does not
re-implement the Sigma YAML parser — rules are loaded with
`SigmaCollection.from_yaml`, and pySigma resolves the condition grammar into an
AND/OR/NOT/leaf tree that this project walks.

To keep evaluation honest and predictable, only a **documented subset** is
supported. Anything outside it raises `UnsupportedFeatureError` with a clear
message rather than silently mis-matching.

---

## Supported

### Field-value modifiers (leaf matching)
| Construct | Sigma example | Semantics |
|-----------|---------------|-----------|
| equals | `Field: value` | case-insensitive exact match |
| `contains` | `Field|contains: x` | substring |
| `startswith` | `Field|startswith: x` | prefix |
| `endswith` | `Field|endswith: x` | suffix |
| `all` | `Field|contains|all: [a, b]` | AND across the listed values |
| `re` | `Field|re: 'pat'` | regular expression (`re.search`) |
| `null` | `Field: null` | field absent or null |
| numeric compare | `Field|gte: 8000` | `gt` / `gte` / `lt` / `lte` / `neq` (numeric) |

> Numeric comparison is a deliberate extension beyond the original brief's base
> subset — it makes consumption/threshold detections (e.g. token spikes)
> fire-testable.

### Condition grammar (resolved by pySigma)
- `sel and not filter`
- `1 of sel_*`, `all of sel_*`, `1 of them`, `all of them`
- value **lists = OR**; multiple fields in a map = **AND**
- keyword (free-text) detections — matched against all scalar values in the event

### Correlation rules
Sigma correlation rules are supported for **`event_count`** and **`value_count`**:

- `group-by` one or more fields, a `timespan`, and a `condition` (`gte` / `gt` /
  `lte` / `lt` / `eq` / `neq`; `value_count` also takes a `field`).
- The evaluator matches events against the base rule(s), buckets them by the
  group-by key, and slides a `timespan` window over each bucket (using the event
  `timestamp`), triggering when the count / distinct-value count crosses the
  threshold.
- **Fire-test fixtures for correlations are scenarios**: the `*.positive.json`
  event set must trigger the correlation, the `*.negative.json` set must not.
- **Backend support:** correlations convert to **Splunk SPL** only. The Kusto
  backend raises `NotImplementedError` for correlations, so that target is skipped
  (documented, not silent).
- **Windowing caveat (sliding vs. tumbling):** the offline evaluator uses a
  **sliding** `timespan` window (any window of `timespan` length triggers), so it
  is *at least as sensitive* as the deployed query. pySigma's Splunk backend emits
  `bin _time span=<timespan>` — i.e. **fixed/tumbling** buckets — so events that
  straddle a bucket boundary (e.g. 14:09/14:10/14:11 for a 10m rule) can be split
  across two buckets in Splunk and miss, even though the evaluator (and intent)
  would alert. Tune the deployed `bin`/window strategy to your SIEM; the fixtures
  here keep bursts within a single bucket so both agree.
- `temporal*` and `value_sum/avg/percentile/median` correlation types are **not**
  implemented by the offline evaluator and raise a clear error.

### Field resolution
Both **flat dotted keys** (`{"llm.prompt": "..."}`) and **nested objects**
(`{"llm": {"prompt": "..."}}`) are resolved, so the same rule works against
either event shape.

---

## Not supported (raises a clear error)
`base64` / `base64offset` expansion, `cidr`, `fieldref`, `|expand`, placeholder
(`%var%`) expansion, and correlation types other than `event_count` /
`value_count` (`temporal*`, `value_sum/avg/percentile/median`). These convert
fine to SPL/KQL via the backends, but the offline evaluator refuses to guess at
them.

---

## Synthetic `llm_app` event schema

A fictional, product-agnostic "LLM gateway/app" event. Defined in
`src/sigmaforge/llm_schema.py`; rules in `rules/llm/` reference these exact field
names.

| Field | Type | Meaning |
|-------|------|---------|
| `timestamp` | string | ISO-8601 event time |
| `user.id` | string | pseudonymous caller identity |
| `app.id` | string | logical application / tenant |
| `llm.model` | string | model the request targeted |
| `llm.prompt` | string | prompt text sent to the model |
| `llm.completion` | string | completion text returned |
| `llm.prompt_tokens` | integer | prompt token count |
| `llm.completion_tokens` | integer | completion token count |
| `request.source_ip` | string | request source IP |
| `tool.name` | string | tool/function the model could call |
| `tool.target_host` | string | host a tool action targeted |

### Pipeline mappings
- **Splunk** (`pipelines/llm_splunk.yml`): dotted fields are flattened to
  underscore field names (`llm.prompt` → `llm_prompt`).
- **KQL** (`pipelines/llm_kusto.yml`): fields map to columns on a custom Log
  Analytics table `LLMAppLogs_CL` (`llm.prompt` → `PromptText`, …). The table is
  set via the Kusto backend's `query_table` pipeline state. See **Limitations**
  in the README for caveats about custom tables vs. Microsoft-native schemas.
