"""Compile Sigma rules to Splunk SPL and Microsoft KQL with pySigma.

Conversion runs in-process through pySigma backends (never by shelling out to
``sigma``), so output is deterministic and snapshot-tested.

Each target pairs a backend with one processing pipeline per log family:

============  ==========================  ======================  =============================
Target        Query language              ``windows`` rules       ``llm_app`` rules
============  ==========================  ======================  =============================
``splunk``    Splunk SPL                  Sysmon pipeline         ``pipelines/llm_splunk.yml``
``defender``  Microsoft Defender XDR KQL  Microsoft XDR pipeline  (not applicable)
``sentinel``  Microsoft Sentinel KQL      Sentinel ASIM pipeline  ``pipelines/llm_sentinel.yml``
============  ==========================  ======================  =============================

Correlation rules compile to Splunk only: the Kusto backend raises
``NotImplementedError`` for Sigma correlations, so the KQL targets do not apply
to them. The Splunk SPL2 backend was evaluated and deliberately not shipped: it
emits mixed ``AND``/``OR`` ``WHERE`` clauses without grouping parentheses,
which changes operator precedence and broadens the query.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources

from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend
from sigma.processing.pipeline import ProcessingPipeline

from .workspace import Family, RuleFile


class ConversionError(RuntimeError):
    """A backend could not compile a rule."""


@dataclass(frozen=True)
class Target:
    id: str
    label: str
    language: str
    families: frozenset[Family]
    correlations: bool

    def applies_to(self, rule: RuleFile) -> bool:
        return rule.family in self.families and (self.correlations or rule.correlation is None)


TARGETS: Mapping[str, Target] = {
    t.id: t
    for t in (
        Target("splunk", "Splunk SPL", "spl", frozenset(Family), correlations=True),
        Target("defender", "Defender XDR KQL", "kql", frozenset({Family.WINDOWS}), False),
        Target("sentinel", "Sentinel KQL", "kql", frozenset(Family), correlations=False),
    )
}


def targets_for(rule: RuleFile) -> list[Target]:
    return [t for t in TARGETS.values() if t.applies_to(rule)]


def _packaged_pipeline(filename: str) -> ProcessingPipeline:
    text = resources.files("sigmaforge").joinpath("pipelines", filename).read_text(encoding="utf-8")
    return ProcessingPipeline.from_yaml(text)


@cache
def _pipeline(target_id: str, family: Family) -> ProcessingPipeline:
    if family is Family.LLM:
        if target_id == "splunk":
            return _packaged_pipeline("llm_splunk.yml")
        from sigma.pipelines.kusto_common.postprocessing import (
            PrependQueryTablePostprocessingTransformation,
            QueryPostprocessingItem,
        )

        pipeline = _packaged_pipeline("llm_sentinel.yml")
        pipeline.postprocessing_items = [
            *pipeline.postprocessing_items,
            QueryPostprocessingItem(
                transformation=PrependQueryTablePostprocessingTransformation(),
                identifier="llm_prepend_query_table",
            ),
        ]
        return pipeline
    if target_id == "splunk":
        from sigma.pipelines.sysmon import sysmon_pipeline

        pipeline = sysmon_pipeline()
    elif target_id == "defender":
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

        pipeline = microsoft_xdr_pipeline()
    else:
        from sigma.pipelines.sentinelasim import sentinel_asim_pipeline

        pipeline = sentinel_asim_pipeline()
    return pipeline


@cache
def _backend(target_id: str, family: Family) -> Backend:
    pipeline = _pipeline(target_id, family)
    if target_id == "splunk":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend(processing_pipeline=pipeline)
    from sigma.backends.kusto import KustoBackend

    # KustoBackend annotates processing_pipeline as a dict; it accepts pipelines at runtime.
    return KustoBackend(processing_pipeline=pipeline)  # type: ignore[arg-type]


def convert(rule: RuleFile, target_id: str) -> str:
    """Compile ``rule`` for one target, raising :class:`ConversionError` on failure."""
    target = TARGETS[target_id]
    if rule.family is None or not target.applies_to(rule):
        raise ConversionError(f"{target.label} does not apply to {rule.name}")
    try:
        # Parse afresh: processing pipelines rewrite field names on the rule objects
        # in place, and the shared RuleFile collection must keep Sigma field names.
        collection = SigmaCollection.from_yaml(rule.text)
        queries = _backend(target_id, rule.family).convert(collection)
    except Exception as exc:  # backends and pipelines raise many exception types
        raise ConversionError(f"{target.label}: {exc}") from exc
    query = "\n\n".join(str(q) for q in queries).strip()
    if not query:
        raise ConversionError(f"{target.label}: the backend produced no query")
    return query


def convert_rule(rule: RuleFile) -> dict[str, str]:
    """Compile ``rule`` for every applicable target, in :data:`TARGETS` order."""
    return {target.id: convert(rule, target.id) for target in targets_for(rule)}
