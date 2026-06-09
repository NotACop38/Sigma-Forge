"""Convert Sigma rules to Splunk SPL/SPL2 and Microsoft Sentinel/Defender KQL.

Conversion runs entirely through pySigma (no shelling out to the ``sigma`` CLI),
so results are deterministic and snapshot-testable.

Targets (each knows which rule *kinds* it supports):

==============  ============================  ====================  ==========================
Target id       Query language                Backend               Applies to
==============  ============================  ====================  ==========================
``splunk``      Splunk SPL                    SplunkBackend         classic, llm, correlation
``kusto``       Microsoft Defender/XDR KQL    KustoBackend          classic, llm
``sentinel``    Microsoft Sentinel ASIM KQL   KustoBackend          classic
==============  ============================  ====================  ==========================

Pipelines are chosen per (target, kind):

* classic ``process_creation`` -> Sysmon (SPL), Microsoft XDR (kusto),
  Sentinel ASIM (sentinel).
* custom ``llm_app`` -> the repo-local pipelines under ``pipelines/`` (KQL targets
  the custom ``LLMAppLogs_CL`` table).
* correlation rules -> Splunk only; the Kusto backend raises
  ``NotImplementedError`` for correlations, which we surface as a documented skip.

Note: the Splunk **SPL2** backend was evaluated and intentionally NOT shipped — it
emits mixed ``AND``/``OR`` ``WHERE`` clauses without grouping parentheses, which
changes operator precedence and makes the query broader than the Sigma rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

# Repo roots ---------------------------------------------------------------
_PKG_ROOT = Path(__file__).resolve().parent
REPO_ROOT = _PKG_ROOT.parent.parent
RULES_ROOT = REPO_ROOT / "rules"
PIPELINES_ROOT = REPO_ROOT / "pipelines"

# Rule kinds.
CLASSIC, LLM, CORRELATION = "classic", "llm", "correlation"


@dataclass(frozen=True)
class Target:
    """A conversion target: a backend + the rule kinds it can express."""

    id: str
    label: str
    lang: str  # syntax-highlighting hint for the CLI
    kinds: frozenset[str]

    def applies(self, kind: str) -> bool:
        return kind in self.kinds


TARGETS: dict[str, Target] = {
    "splunk": Target("splunk", "Splunk SPL", "text", frozenset({CLASSIC, LLM, CORRELATION})),
    "kusto": Target("kusto", "Microsoft Defender/XDR KQL", "kql", frozenset({CLASSIC, LLM})),
    "sentinel": Target("sentinel", "Microsoft Sentinel KQL (ASIM)", "kql", frozenset({CLASSIC})),
}
TARGET_IDS = tuple(TARGETS)
# Backwards-compatible labels mapping used by the CLI.
TARGET_LABELS = {t.id: t.label for t in TARGETS.values()}


class ConversionError(RuntimeError):
    """Raised when a rule cannot be converted by a backend."""


@dataclass
class RuleConversion:
    """Converted queries for a single rule file, keyed by target id."""

    name: str
    path: Path
    kind: str
    queries: dict[str, str]

    def query(self, target: str) -> str:
        return self.queries.get(target, "")


# --- rule-kind classification --------------------------------------------

def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]


def rule_kind(path: Path) -> str:
    """Return ``classic`` / ``llm`` / ``correlation`` for a rule file."""
    docs = _docs(path)
    if any("correlation" in d for d in docs):
        return CORRELATION
    for d in docs:
        logsource = d.get("logsource", {}) or {}
        if "llm" in (logsource.get("category") or "").lower() or "llm" in (
            logsource.get("product") or ""
        ).lower():
            return LLM
    return CLASSIC


# --- pipeline construction (cached) ---------------------------------------

@cache
def _llm_pipeline(target_id: str) -> ProcessingPipeline:
    fname = "llm_splunk.yml" if target_id == "splunk" else "llm_kusto.yml"
    pipeline = ProcessingPipeline.from_yaml((PIPELINES_ROOT / fname).read_text(encoding="utf-8"))
    if target_id in {"kusto", "sentinel"}:
        from sigma.pipelines.kusto_common.postprocessing import (
            PrependQueryTablePostprocessingTransformation,
            QueryPostprocessingItem,
        )

        pipeline.postprocessing_items = [
            *pipeline.postprocessing_items,
            QueryPostprocessingItem(
                transformation=PrependQueryTablePostprocessingTransformation(),
                identifier="llm_prepend_query_table",
            ),
        ]
    return pipeline


def _pipeline_kind(kind: str, rule_yaml: str) -> str:
    """Map a rule kind to which field-mapping pipeline family to use (classic|llm).

    Correlation rules inherit the family of their base rule's logsource.
    """
    if kind == LLM:
        return LLM
    if kind == CORRELATION:
        for d in yaml.safe_load_all(rule_yaml):
            if not isinstance(d, dict):
                continue
            ls = d.get("logsource", {}) or {}
            if "llm" in (ls.get("category") or "").lower() or "llm" in (
                ls.get("product") or ""
            ).lower():
                return LLM
    return CLASSIC


@cache
def _pipeline(target_id: str, pkind: str) -> ProcessingPipeline:
    if pkind == LLM:
        return _llm_pipeline(target_id)
    if target_id == "splunk":
        from sigma.pipelines.sysmon import sysmon_pipeline

        return sysmon_pipeline()
    if target_id == "kusto":
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

        return microsoft_xdr_pipeline()
    from sigma.pipelines.sentinelasim import sentinel_asim_pipeline

    return sentinel_asim_pipeline()


@cache
def _backend(target_id: str, pkind: str):
    pipeline = _pipeline(target_id, pkind)
    if target_id == "splunk":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend(processing_pipeline=pipeline)
    from sigma.backends.kusto import KustoBackend

    return KustoBackend(processing_pipeline=pipeline)  # type: ignore[arg-type]


# --- conversion -----------------------------------------------------------

def convert_text(rule_yaml: str, target: str, kind: str = CLASSIC) -> str:
    """Convert a rule document (possibly multi-doc) to one query string for ``target``."""
    collection = SigmaCollection.from_yaml(rule_yaml)
    backend = _backend(target, _pipeline_kind(kind, rule_yaml))
    try:
        queries = backend.convert(collection)
    except Exception as exc:  # pragma: no cover - surfaced as ConversionError
        raise ConversionError(f"{target} backend failed: {exc}") from exc
    return "\n\n".join(str(q) for q in queries).strip()


def convert_file(path: Path) -> RuleConversion:
    """Convert one rule file to every applicable target."""
    path = Path(path)
    kind = rule_kind(path)
    text = path.read_text(encoding="utf-8")
    queries: dict[str, str] = {}
    for tid, target in TARGETS.items():
        if target.applies(kind):
            queries[tid] = convert_text(text, tid, kind)
    return RuleConversion(name=path.stem, path=path, kind=kind, queries=queries)


def targets_for(kind: str) -> list[str]:
    return [tid for tid, t in TARGETS.items() if t.applies(kind)]


def iter_rule_files(paths: list[Path] | None = None) -> list[Path]:
    """Return all rule files (single- or multi-doc) under the given paths (default: rules/)."""
    if not paths:
        paths = [RULES_ROOT]
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.yml")))
        elif p.suffix in {".yml", ".yaml"}:
            files.append(p)
    rules = []
    for f in files:
        try:
            docs = _docs(f)
        except yaml.YAMLError as exc:
            # A broken rule must fail loudly, not silently drop out of lint/convert/fire-test.
            raise ConversionError(f"{f} is not valid YAML: {exc}") from exc
        if any("detection" in d or "correlation" in d for d in docs):
            rules.append(f)
    return rules


def convert_all(paths: list[Path] | None = None) -> list[RuleConversion]:
    return [convert_file(f) for f in iter_rule_files(paths)]
