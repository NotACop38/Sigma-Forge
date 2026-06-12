"""Coverage tests: the Navigator layer is valid v4.x JSON with real technique IDs."""

from __future__ import annotations

import re

import pytest

from sigmaforge import coverage as cov

_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_collects_real_attack_techniques():
    data = cov.collect_coverage()
    assert data.attack_technique_count >= 3
    for tech in data.technique_rules:
        assert _TECH.match(tech), f"{tech} is not a valid ATT&CK technique ID"


def test_techniques_pair_with_their_canonical_tactic():
    """A rule tagging several tactics must not smear them across all its techniques.

    win_encoded_powershell tags execution + defense-evasion for T1059.001 + T1027;
    T1027 is canonically Defense Evasion only, and T1105 (certutil) is Command and
    Control only — the heatmap previously labelled both with the wrong tactic.
    """
    data = cov.collect_coverage()
    assert data.technique_tactics["T1027"] == {"defense-evasion"}
    assert data.technique_tactics["T1059.001"] == {"execution"}
    assert data.technique_tactics["T1105"] == {"command-and-control"}
    assert data.technique_tactics["T1140"] == {"defense-evasion"}


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


def test_build_site_refreshes_previous_bundle(tmp_path):
    """A directory holding only a previous site bundle is cleaned and rebuilt."""
    site = tmp_path / "_site"
    cov.build_site(site)
    (site / "attack-layer.json").write_text("stale", encoding="utf-8")

    cov.build_site(site)

    assert (site / "attack-layer.json").read_text(encoding="utf-8") != "stale"
    assert sorted(path.name for path in site.iterdir()) == [
        "attack-layer.json",
        "attack-layer.png",
        "index.html",
    ]


def test_build_site_refuses_directory_with_foreign_files(tmp_path):
    """`--site docs` (or any populated dir) must refuse instead of rmtree'ing it."""
    site = tmp_path / "docs"
    site.mkdir()
    precious = site / "threat-model.md"
    precious.write_text("do not delete", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to clean"):
        cov.build_site(site)

    assert precious.read_text(encoding="utf-8") == "do not delete"


def test_build_site_replaces_symlink_before_writing(tmp_path):
    target = tmp_path / "fake_checkout" / ".git"
    target.mkdir(parents=True)
    protected = target / "config"
    protected.write_text("token-like checkout metadata", encoding="utf-8")
    site = tmp_path / "_site"
    site.symlink_to(target, target_is_directory=True)

    if not site.is_symlink():
        pytest.skip("filesystem does not support directory symlinks")

    cov.build_site(site)

    assert not site.is_symlink()
    assert site.is_dir()
    assert protected.read_text(encoding="utf-8") == "token-like checkout metadata"
    assert not (target / "index.html").exists()
    assert (site / "index.html").exists()
