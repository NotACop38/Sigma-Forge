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


def test_collect_coverage_rejects_excessive_attack_techniques(tmp_path):
    tags = "\n".join(f"  - attack.t{i:04d}" for i in range(cov._MAX_ATTACK_TECHNIQUES + 1))
    rule = tmp_path / "too_many_tags.yml"
    rule.write_text(
        f"""title: Excessive ATTACK Tags
id: 49f60f5d-7ba7-4ad0-b239-41e75c2dcb4e
status: experimental
description: Synthetic rule used to verify coverage input limits.
author: sigma-forge
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
falsepositives:
  - Synthetic test fixture.
level: low
tags:
{tags}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="safety limit"):
        cov.collect_coverage([rule])


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


def test_build_site_removes_stale_files(tmp_path):
    site = tmp_path / "_site"
    site.mkdir()
    stale = site / "stale.txt"
    stale.write_text("do not publish", encoding="utf-8")

    cov.build_site(site)

    assert not stale.exists()
    assert sorted(path.name for path in site.iterdir()) == [
        "attack-layer.json",
        "attack-layer.png",
        "index.html",
    ]


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
