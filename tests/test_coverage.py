"""Coverage tests: the Navigator layer is valid v4.x JSON with real technique IDs."""

from __future__ import annotations

import re

from sigmaforge import coverage as cov

_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_collects_real_attack_techniques():
    data = cov.collect_coverage()
    assert data.attack_technique_count >= 3
    for tech in data.technique_rules:
        assert _TECH.match(tech), f"{tech} is not a valid ATT&CK technique ID"


def test_layer_is_valid_navigator_v4():
    layer = cov.build_layer(cov.collect_coverage())
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"].startswith("4.")
    assert layer["techniques"], "layer has no techniques"
    for t in layer["techniques"]:
        assert _TECH.match(t["techniqueID"])
        assert isinstance(t["score"], int)


def test_build_coverage_writes_files(tmp_path):
    layer = tmp_path / "layer.json"
    png = tmp_path / "img" / "heat.png"
    summary = cov.build_coverage(layer_path=layer, png_path=png)
    assert layer.exists() and png.exists()
    assert summary.attack_technique_count >= 3


def test_build_site_emits_pages_bundle(tmp_path):
    site = tmp_path / "_site"
    summary = cov.build_site(site)
    for name in ("index.html", "attack-layer.png", "attack-layer.json"):
        assert (site / name).exists(), f"missing {name}"
    html = (site / "index.html").read_text(encoding="utf-8")
    assert str(summary.attack_technique_count) in html
