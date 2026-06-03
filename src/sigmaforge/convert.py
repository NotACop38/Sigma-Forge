"""Convert Sigma rules to Splunk SPL and Microsoft Sentinel/Defender KQL.

Conversion runs entirely through pySigma (no shelling out to the ``sigma`` CLI),
so results are deterministic and snapshot-testable. The right processing
pipeline is chosen per rule from its ``logsource``:

* ``process_creation`` (classic pack) -> Sysmon pipeline for SPL, Microsoft XDR
  pipeline for KQL.
* custom ``llm_app`` logsource (AI/LLM pack) -> the repo-local pipelines under
  ``pipelines/`` that map the synthetic LLM-gateway schema.
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

# Backend target identifiers we emit for every rule.
TARGETS = ("splunk", "kusto")
TARGET_LABELS = {"splunk": "Splunk SPL", "kusto": "Microsoft Sentinel/Defender KQL"}


class ConversionError(RuntimeError):
    """Raised when a rule cannot be converted by a backend."""


@dataclass
class RuleConversion:
    """SPL and KQL output for a single rule file."""

    name: str
    path: Path
    splunk: str
    kusto: str

    def query(self, target: str) -> str:
        return {"splunk": self.splunk, "kusto": self.kusto}[target]


# --- logsource classification --------------------------------------------

def _logsource_kind(path: Path) -> str:
    """Return ``"classic"`` or ``"llm"`` based on a rule's logsource block."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    logsource = (doc or {}).get("logsource", {}) or {}
    category = (logsource.get("category") or "").lower()
    product = (logsource.get("product") or "").lower()
    if "llm" in category or "llm" in product:
        return "llm"
    return "classic"


# --- pipeline construction (cached; pipelines are pure/stateless here) ----

@cache
def _classic_pipeline(target: str) -> ProcessingPipeline:
    if target == "splunk":
        from sigma.pipelines.sysmon import sysmon_pipeline

        return sysmon_pipeline()
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    return microsoft_xdr_pipeline()


@cache
def _llm_pipeline(target: str) -> ProcessingPipeline:
    fname = {"splunk": "llm_splunk.yml", "kusto": "llm_kusto.yml"}[target]
    pipeline = ProcessingPipeline.from_yaml((PIPELINES_ROOT / fname).read_text(encoding="utf-8"))
    if target == "kusto":
        # The Kusto backend prepends the destination table via a postprocessing
        # transformation that is not YAML-registerable, so we attach it here. This
        # lets the custom `llm_app` logsource emit `LLMAppLogs_CL | where ...`.
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


def _pipeline_for(kind: str, target: str) -> ProcessingPipeline:
    return _classic_pipeline(target) if kind == "classic" else _llm_pipeline(target)


@cache
def _backend(target: str, kind: str):
    pipeline = _pipeline_for(kind, target)
    if target == "splunk":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend(processing_pipeline=pipeline)
    from sigma.backends.kusto import KustoBackend

    return KustoBackend(processing_pipeline=pipeline)  # type: ignore[arg-type]


# --- conversion -----------------------------------------------------------

def convert_text(rule_yaml: str, target: str, kind: str = "classic") -> str:
    """Convert a single rule's YAML text to one query string for ``target``."""
    collection = SigmaCollection.from_yaml(rule_yaml)
    backend = _backend(target, kind)
    try:
        queries = backend.convert(collection)
    except Exception as exc:  # pragma: no cover - surfaced as ConversionError
        raise ConversionError(f"{target} backend failed: {exc}") from exc
    return "\n".join(str(q) for q in queries).strip()


def convert_file(path: Path) -> RuleConversion:
    """Convert one rule file to both SPL and KQL."""
    path = Path(path)
    kind = _logsource_kind(path)
    text = path.read_text(encoding="utf-8")
    return RuleConversion(
        name=path.stem,
        path=path,
        splunk=convert_text(text, "splunk", kind),
        kusto=convert_text(text, "kusto", kind),
    )


def iter_rule_files(paths: list[Path] | None = None) -> list[Path]:
    """Return all ``*.yml`` rule files under the given paths (default: rules/)."""
    if not paths:
        paths = [RULES_ROOT]
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.yml")))
        elif p.suffix in {".yml", ".yaml"}:
            files.append(p)
    # Skip non-rule yaml (e.g. license placeholders) by requiring a detection block.
    rules = []
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and "detection" in doc:
            rules.append(f)
    return rules


def convert_all(paths: list[Path] | None = None) -> list[RuleConversion]:
    return [convert_file(f) for f in iter_rule_files(paths)]
