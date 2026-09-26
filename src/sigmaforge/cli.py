"""sigma-forge command-line interface.

Commands:
  check     Lint, convert, and fire-test rules (the CI gate).
  convert   Print the compiled Splunk SPL / Microsoft KQL for rules.
  coverage  Write (or verify) the ATT&CK Navigator layer and the SVG coverage card.
  draft     Draft a rule and fixtures with a local LLM, validated by the same gate.

Exit codes: 0 success, 1 a gate failed, 2 usage error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from . import convert as convert_mod
from .workspace import RuleLoadError, Workspace, load_rule

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
    help="Detection-as-code for Sigma: lint, convert to SPL and KQL, and fire-test rules.",
)
console = Console(highlight=False)

_LEXERS = {"spl": "text", "kql": "kql"}
_FIRE_TEST_LEGEND = (
    "fire-test: +fired/positives −silent/negatives (correlations count scenarios)\n"
    "–: the target does not apply to the rule's log family"
)
_PATHS = typer.Argument(None, help="Rule files or directories (default: every rule).")
_ROOT = typer.Option(
    None,
    "--root",
    help="Workspace root (default: nearest directory, upwards, that contains rules/).",
    file_okay=False,
    exists=True,
)


def _fail(message: str, code: int = 1) -> NoReturn:
    # escape(): messages embed rule-controlled text that must not act as Rich markup.
    console.print(f"[red]error:[/red] {escape(message)}")
    raise typer.Exit(code)


def _workspace(root: Path | None) -> Workspace:
    return Workspace(root) if root is not None else Workspace.discover()


def _version(value: bool) -> None:
    if value:
        console.print(f"sigma-forge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version_flag: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """Detection-as-code for Sigma: lint, convert to SPL and KQL, and fire-test rules."""


@app.command()
def check(
    paths: list[Path] | None = _PATHS,
    root: Path | None = _ROOT,
    as_json: bool = typer.Option(False, "--json", help="Print a machine-readable report."),
) -> None:
    """Lint, convert, and fire-test rules. Exits 1 if any rule fails."""
    from .check import run_check

    workspace = _workspace(root)
    try:
        report = run_check(workspace, paths or None)
    except RuleLoadError as exc:
        _fail(str(exc), 2)

    if as_json:
        typer.echo(json.dumps(report.as_dict(), indent=2))
        raise typer.Exit(0 if report.passed else 1)

    targets = list(convert_mod.TARGETS.values())
    table = Table(box=box.SIMPLE_HEAVY, pad_edge=False, collapse_padding=True)
    table.add_column("rule", no_wrap=True, overflow="ellipsis")
    for header in ("lint", *(t.id for t in targets), "fire-test"):
        table.add_column(header, justify="center", no_wrap=True, min_width=len(header))

    for rule in report.rules:
        cells = ["[green]✓[/green]" if not rule.lint else f"[red]✗ {len(rule.lint)}[/red]"]
        for target in targets:
            if target.id not in rule.conversions:
                cells.append("[dim]–[/dim]")
            else:
                ok = rule.conversions[target.id] is None
                cells.append("[green]✓[/green]" if ok else "[red]✗[/red]")
        if rule.firetest is None:
            cells.append("[dim]–[/dim]")
        else:
            (fired, positives), (silent, negatives) = (
                rule.firetest.positives,
                rule.firetest.negatives,
            )
            color = "green" if rule.firetest.passed else "red"
            cells.append(f"[{color}]+{fired}/{positives} −{silent}/{negatives}[/{color}]")
        mark = "[green]✓[/green]" if rule.passed else "[bold red]✗[/bold red]"
        table.add_row(f"{mark} [cyan]{escape(rule.name)}[/cyan]", *cells)
    console.print(table)

    for rule in report.rules:
        if not rule.passed:
            console.print(f"[bold red]{escape(rule.path)}[/bold red]")
            for problem in rule.problems():
                console.print(f"  • {escape(problem)}")
    for issue in report.workspace_issues:
        console.print(f"[bold red]workspace:[/bold red] {escape(issue)}")

    failed = sum(not r.passed for r in report.rules)
    if report.passed:
        console.print(f"[green]{len(report.rules)} rules passed[/green]")
        console.print(f"[dim]{_FIRE_TEST_LEGEND}[/dim]")
        return
    console.print(f"[bold red]{failed} of {len(report.rules)} rules failed[/bold red]")
    console.print(f"[dim]{_FIRE_TEST_LEGEND}[/dim]")
    raise typer.Exit(1)


@app.command()
def convert(
    paths: list[Path] | None = _PATHS,
    target: str | None = typer.Option(
        None, "--target", "-t", help=f"Only this target: {', '.join(convert_mod.TARGETS)}."
    ),
    root: Path | None = _ROOT,
) -> None:
    """Print the compiled queries for each rule. Exits 1 if any conversion fails."""
    if target is not None and target not in convert_mod.TARGETS:
        _fail(f"unknown target {target!r}; choose from {', '.join(convert_mod.TARGETS)}", 2)
    workspace = _workspace(root)
    try:
        rule_paths = workspace.rule_paths(paths or None)
    except RuleLoadError as exc:
        _fail(str(exc), 2)

    failures = 0
    for path in rule_paths:
        console.rule(f"[bold cyan]{escape(path.stem)}")
        try:
            rule = load_rule(path)
        except RuleLoadError as exc:
            failures += 1
            console.print(f"[red]cannot load:[/red] {escape(str(exc))}")
            continue
        applicable = [t for t in convert_mod.targets_for(rule) if target in (None, t.id)]
        if not applicable:
            console.print(
                f"[dim]{escape(target or 'no target')}: not applicable to this rule[/dim]"
            )
        for spec in applicable:
            console.print(f"[bold]{spec.label}[/bold]")
            try:
                query = convert_mod.convert(rule, spec.id)
            except convert_mod.ConversionError as exc:
                failures += 1
                console.print(f"[red]{escape(str(exc))}[/red]")
                continue
            console.print(Syntax(query, _LEXERS[spec.language], theme="ansi_dark", word_wrap=True))
    if failures:
        _fail(f"{failures} conversion(s) failed")


@app.command()
def coverage(
    root: Path | None = _ROOT,
    layer: Path = typer.Option(Path("docs/attack-layer.json"), help="Navigator layer path."),
    svg: Path = typer.Option(Path("docs/images/coverage.svg"), help="Coverage card path."),
    check_only: bool = typer.Option(
        False, "--check", help="Write nothing; exit 1 if the files are out of date."
    ),
) -> None:
    """Write the ATT&CK Navigator layer and the SVG coverage card (paths are root-relative)."""
    from . import coverage as coverage_mod

    workspace = _workspace(root)
    try:
        rules = [load_rule(path) for path in workspace.rule_paths()]
    except RuleLoadError as exc:
        _fail(str(exc))
    report = coverage_mod.collect(rules)
    files = coverage_mod.artifacts(report, workspace.root / layer, workspace.root / svg)
    if check_only:
        stale = coverage_mod.stale_artifacts(files)
        if stale:
            names = ", ".join(workspace.display(p) for p in stale)
            _fail(f"out of date: {names}; run `sigma-forge coverage` and commit the result")
        console.print("[green]coverage artifacts are up to date[/green]")
        return
    coverage_mod.write_artifacts(files)
    console.print(
        f"[green]wrote[/green] {', '.join(workspace.display(p) for p in files)}: "
        f"{len(report.attack)} ATT&CK and {len(report.atlas)} ATLAS techniques, "
        f"{len(report.owasp)} OWASP LLM risks across {len(report.detections)} detections"
    )


@app.command()
def draft(
    threat: str = typer.Argument(..., help="Plain-English description of the threat."),
    write: bool = typer.Option(False, "--write", help="Write the accepted rule and fixtures."),
    name: str | None = typer.Option(None, help="File name stem for --write (default: from title)."),
    base_url: str | None = typer.Option(
        None, help="OpenAI-compatible base URL (default: $SIGMA_FORGE_LLM_BASE_URL or loopback)."
    ),
    model: str | None = typer.Option(None, help="Model name (default: $SIGMA_FORGE_LLM_MODEL)."),
    attempts: int = typer.Option(3, min=1, max=5, help="Draft plus repair attempts."),
    timeout: float = typer.Option(120.0, min=1.0, help="Per-request timeout in seconds."),
    allow_remote: bool = typer.Option(
        False, "--allow-remote", help="Permit a non-loopback endpoint (sends the threat text)."
    ),
    root: Path | None = _ROOT,
) -> None:
    """Draft a rule with a local LLM; accept it only if it passes the full gate."""
    from . import draft as draft_mod

    try:
        if name is not None:
            draft_mod.check_name(name)  # fail before spending a model call
        client = draft_mod.ChatCompletionsClient(
            draft_mod.Endpoint.from_env(base_url, model, timeout), allow_remote=allow_remote
        )
        result = draft_mod.draft_rule(threat, client, attempts=attempts)
    except draft_mod.DraftError as exc:
        _fail(str(exc))

    for number, attempt in enumerate(result.attempts, start=1):
        verdict = "[green]accepted[/green]" if attempt.accepted else "[red]rejected[/red]"
        console.print(f"attempt {number}/{attempts}: {verdict}")
        for stage, message in attempt.errors:
            console.print(f"  • {stage}: {escape(message)}")

    final = result.final
    if final.draft is not None:
        console.print(Syntax(final.draft.rule_yaml, "yaml", theme="ansi_dark"))
    if not result.accepted:
        _fail("no draft passed the gate; nothing was written")
    for target_id, query in final.queries.items():
        spec = convert_mod.TARGETS[target_id]
        console.print(f"[bold]{spec.label}[/bold]")
        console.print(Syntax(query, _LEXERS[spec.language], theme="ansi_dark", word_wrap=True))
    if write:
        workspace = _workspace(root)
        try:
            written = draft_mod.write_draft(final, workspace, name)
        except draft_mod.DraftError as exc:
            _fail(str(exc))
        for path in written:
            console.print(f"[green]wrote[/green] {workspace.display(path)}")
        console.print("next: review the rule and events, then run `make golden` and `make test`")


if __name__ == "__main__":  # pragma: no cover
    app()
