"""End-to-end CLI behaviour: output, exit codes, and file effects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from sigmaforge import __version__, draft
from sigmaforge.cli import app
from tests.support import (
    REPO_ROOT,
    WINDOWS_NEGATIVE,
    WINDOWS_POSITIVE,
    WINDOWS_RULE,
    make_workspace,
)
from tests.test_draft import GOOD

runner = CliRunner()
ROOT = ["--root", str(REPO_ROOT)]
FIXTURES = {
    "classic/win_whoami.positive": WINDOWS_POSITIVE,
    "classic/win_whoami.negative": WINDOWS_NEGATIVE,
}


def invoke(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, list(args))
    return result.exit_code, result.output


def test_version() -> None:
    assert invoke("--version") == (0, f"sigma-forge {__version__}\n")


def test_check_passes_on_the_repository() -> None:
    code, output = invoke("check", *ROOT)
    assert code == 0, output
    assert "rules passed" in output
    assert "llm_prompt_injection_burst" in output


def test_check_json_report() -> None:
    code, output = invoke("check", *ROOT, "--json")
    report = json.loads(output)
    assert code == 0
    assert report["passed"] is True
    assert {rule["name"] for rule in report["rules"]} >= {"win_encoded_powershell"}


def test_check_fails_and_explains(tmp_path: Path) -> None:
    fixtures = {**FIXTURES, "classic/win_whoami.negative": WINDOWS_POSITIVE}
    make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE}, fixtures)
    code, output = invoke("check", "--root", str(tmp_path))
    assert code == 1
    assert "fire-test: negative event #1 fired" in output
    assert "1 of 1 rules failed" in output


def test_check_rejects_missing_paths() -> None:
    code, output = invoke("check", *ROOT, str(REPO_ROOT / "rules/nope.yml"))
    assert code == 2
    assert "no such file" in output


def test_convert_prints_every_applicable_target() -> None:
    code, output = invoke(
        "convert", *ROOT, str(REPO_ROOT / "rules/classic/win_wmic_process_create.yml")
    )
    assert code == 0, output
    for label in ("Splunk SPL", "Defender XDR KQL", "Sentinel KQL"):
        assert label in output
    assert "DeviceProcessEvents" in output


def test_convert_target_filter_and_not_applicable() -> None:
    path = str(REPO_ROOT / "rules/llm/llm_token_cost_spike.yml")
    code, output = invoke("convert", *ROOT, path, "--target", "sentinel")
    assert code == 0
    assert "LLMAppLogs_CL" in output
    assert "Splunk SPL" not in output
    code, output = invoke("convert", *ROOT, path, "--target", "defender")
    assert code == 0
    assert "not applicable" in output


def test_convert_rejects_unknown_targets() -> None:
    code, output = invoke("convert", *ROOT, "--target", "splnuk")
    assert code == 2
    assert "unknown target 'splnuk'" in output


def test_convert_fails_on_backend_errors(tmp_path: Path) -> None:
    rule = WINDOWS_RULE.replace("Image|endswith", "Image|cased")
    make_workspace(tmp_path, {"classic/win_whoami": rule, "classic/win_broken": "title: ["})
    code, output = invoke("convert", "--root", str(tmp_path))
    assert code == 1
    assert "cannot load" in output
    assert "conversion(s) failed" in output


def test_coverage_check_passes_on_the_repository() -> None:
    assert invoke("coverage", *ROOT, "--check")[0] == 0


def test_coverage_writes_then_verifies(tmp_path: Path) -> None:
    make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE}, FIXTURES)
    code, output = invoke("coverage", "--root", str(tmp_path), "--check")
    assert code == 1
    assert "out of date" in output
    code, output = invoke("coverage", "--root", str(tmp_path))
    assert code == 0, output
    assert (tmp_path / "docs/images/coverage.svg").is_file()
    assert invoke("coverage", "--root", str(tmp_path), "--check")[0] == 0


class FakeClient:
    responses: ClassVar[list[str]] = []

    def __init__(self, endpoint: draft.Endpoint, *, allow_remote: bool = False) -> None:
        self.endpoint = endpoint

    def __call__(self, messages: list[dict[str, str]]) -> str:
        return self.responses.pop(0)


@pytest.fixture
def fake_model(monkeypatch: pytest.MonkeyPatch) -> type[FakeClient]:
    monkeypatch.setattr(draft, "ChatCompletionsClient", FakeClient)
    return FakeClient


def test_draft_accepts_and_writes(tmp_path: Path, fake_model: type[FakeClient]) -> None:
    fake_model.responses = ["garbage", GOOD]
    code, output = invoke("draft", "whoami recon", "--write", "--root", str(tmp_path))
    assert code == 0, output
    assert "attempt 1/3: rejected" in output
    assert "attempt 2/3: accepted" in output
    assert "wrote rules/classic/win_whoami_execution.yml" in output
    assert (tmp_path / "sample_logs/classic/win_whoami_execution.negative.json").is_file()


def test_draft_rejection_writes_nothing(tmp_path: Path, fake_model: type[FakeClient]) -> None:
    fake_model.responses = ["garbage"]
    code, output = invoke("draft", "x", "--attempts", "1", "--write", "--root", str(tmp_path))
    assert code == 1
    assert "nothing was written" in output
    assert not (tmp_path / "rules").exists()


def test_draft_refuses_remote_endpoints_by_default() -> None:
    code, output = invoke("draft", "x", "--base-url", "https://api.example.com/v1")
    assert code == 1
    assert "--allow-remote" in output


def test_draft_validates_the_name_before_calling_the_model(fake_model: type[FakeClient]) -> None:
    fake_model.responses = []  # any model call would fail with IndexError
    code, output = invoke("draft", "x", "--write", "--name", "Bad Name")
    assert code == 1
    assert "invalid rule name" in output
