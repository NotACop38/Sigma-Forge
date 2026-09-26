"""Integrity of the pinned ATT&CK / ATLAS snapshots and the tag parsers."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sigmaforge import taxonomy


def test_attack_snapshot_is_enterprise_v19() -> None:
    attack = taxonomy.attack()
    assert attack.version == "19.2"
    keys = [t.key for t in attack.tactics]
    assert len(keys) == 15
    assert "stealth" in keys
    assert "defense-impairment" in keys
    assert "defense-evasion" not in keys  # renamed to Stealth in ATT&CK v19


def test_atlas_snapshot() -> None:
    atlas = taxonomy.atlas()
    assert atlas.version == "2026.09"
    assert atlas.techniques["AML.T0051"].name == "LLM Prompt Injection"
    assert atlas.tactic("AML.TA0005") is not None


@pytest.mark.parametrize("matrix", [taxonomy.attack(), taxonomy.atlas()], ids=["attack", "atlas"])
def test_every_technique_maps_to_known_tactics_in_matrix_order(matrix: taxonomy.Matrix) -> None:
    keys = [t.key for t in matrix.tactics]
    for technique in matrix.techniques.values():
        assert technique.tactics, technique.id
        assert set(technique.tactics) <= set(keys), technique.id
        assert list(technique.tactics) == sorted(technique.tactics, key=keys.index), technique.id


def test_display_names_qualify_sub_techniques() -> None:
    attack, atlas = taxonomy.attack(), taxonomy.atlas()
    assert attack.display_name("T1053.005") == "Scheduled Task/Job: Scheduled Task"
    assert attack.display_name("T1027") == "Obfuscated Files or Information"
    assert atlas.display_name("AML.T0051.000") == "LLM Prompt Injection: Direct"


def test_tactic_order_puts_unknown_keys_last() -> None:
    attack = taxonomy.attack()
    assert attack.tactic_order("reconnaissance") == 0
    assert attack.tactic_order("nope") == len(attack.tactics)


@pytest.mark.parametrize(
    ("parser", "tag", "expected"),
    [
        (taxonomy.attack_technique, "t1059.001", "T1059.001"),
        (taxonomy.attack_technique, "execution", None),
        (taxonomy.atlas_id, "t0051.000", "AML.T0051.000"),
        (taxonomy.atlas_id, "ta0005", "AML.TA0005"),
        (taxonomy.atlas_id, "prompt", None),
        (taxonomy.owasp_llm_id, "llm07", "LLM07"),
        (taxonomy.owasp_llm_id, "llm11", None),
        (taxonomy.owasp_llm_id, "a01", None),
    ],
)
def test_tag_parsers(parser: Callable[[str], str | None], tag: str, expected: str | None) -> None:
    assert parser(tag) == expected
