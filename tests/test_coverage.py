"""Coverage aggregation, the Navigator layer, the SVG card, and artifact freshness."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from sigmaforge import coverage
from sigmaforge.workspace import Workspace, load_rule
from tests.support import REPO_ROOT, make_rule, rule_yaml

REPO_COVERAGE = coverage.collect(load_rule(p) for p in Workspace(REPO_ROOT).rule_paths())


def test_committed_artifacts_are_up_to_date() -> None:
    files = coverage.artifacts(
        REPO_COVERAGE, REPO_ROOT / "docs/attack-layer.json", REPO_ROOT / "docs/images/coverage.svg"
    )
    stale = coverage.stale_artifacts(files)
    assert not stale, f"regenerate with `make coverage`: {stale}"


def test_a_correlation_file_counts_as_one_detection() -> None:
    names = [d.name for d in REPO_COVERAGE.detections]
    assert len(names) == len(set(names))
    burst = next(d for d in REPO_COVERAGE.detections if d.name == "llm_prompt_injection_burst")
    assert burst.title == "Repeated Prompt Injection Attempts by One User"
    assert burst.owasp == {"LLM01"}


def test_unknown_or_malformed_tags_are_left_out() -> None:
    rule = make_rule(
        rule_yaml(
            "sel:\n  Image: x\ncondition: sel",
            tags=["attack.t1059.001", "attack.t9999", "atlas.t9999", "owasp.llm42"],
        )
    )
    (detection,) = coverage.collect([rule]).detections
    assert detection.attack == {"T1059.001"}
    assert not detection.atlas
    assert not detection.owasp


def test_navigator_layer() -> None:
    layer = coverage.navigator_layer(REPO_COVERAGE)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"] == {"attack": "19", "navigator": "5.3.2", "layer": "4.5"}
    scored = {t["techniqueID"]: t for t in layer["techniques"] if "score" in t}
    assert set(scored) == set(REPO_COVERAGE.attack)
    assert all(isinstance(t["score"], int) and t["score"] >= 1 for t in scored.values())
    expanded = {t["techniqueID"] for t in layer["techniques"] if t.get("showSubtechniques")}
    assert expanded == {t.split(".")[0] for t in scored if "." in t}


def test_svg_is_well_formed_deterministic_and_labelled() -> None:
    svg = coverage.render_svg(REPO_COVERAGE)
    assert svg == coverage.render_svg(REPO_COVERAGE)
    root = ET.fromstring(svg)
    assert root.get("role") == "img"
    text = "".join(root.itertext())
    for technique in [*REPO_COVERAGE.attack, *REPO_COVERAGE.atlas, *REPO_COVERAGE.owasp]:
        assert technique in text


def test_empty_coverage_renders() -> None:
    svg = coverage.render_svg(coverage.Coverage(()))
    assert "no techniques tagged" in svg
    ET.fromstring(svg)


def test_wrap_truncates_long_text() -> None:
    assert coverage._wrap("Command and Scripting Interpreter", 12, 2) == [
        "Command and",
        "Scripting…",
    ]
    assert coverage._wrap("Supercalifragilistic", 8, 1) == ["Superca…"]


def test_write_and_detect_stale_artifacts(tmp_path: Path) -> None:
    files = coverage.artifacts(REPO_COVERAGE, tmp_path / "layer.json", tmp_path / "img/cov.svg")
    assert coverage.stale_artifacts(files) == list(files)
    coverage.write_artifacts(files)
    assert coverage.stale_artifacts(files) == []
    (tmp_path / "layer.json").write_text("{}", encoding="utf-8")
    assert coverage.stale_artifacts(files) == [tmp_path / "layer.json"]
