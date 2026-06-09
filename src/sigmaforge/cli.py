"""sigma-forge command-line interface.

Subcommands:
  convert   Convert rules to Splunk SPL and Sentinel KQL.
  evaluate  Fire-test rules against synthetic JSON sample logs.
  coverage  Emit an ATT&CK Navigator layer + render a heatmap PNG.
  draft     Draft a new rule from a threat sentence via a LOCAL LLM (validated).
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from . import convert as convert_mod

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="sigma-forge — author Sigma, convert to SPL & KQL, fire-test in CI.",
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sigma-forge {__version__}")
        raise typer.Exit()


def _discover_rules(rule_paths: list[Path] | None) -> list[Path]:
    try:
        return convert_mod.iter_rule_files(rule_paths)
    except convert_mod.ConversionError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """sigma-forge CLI."""


@app.command()
def convert(
    paths: list[Path] | None = typer.Argument(None, help="Rule files/dirs (default: rules/)."),
    all_rules: bool = typer.Option(False, "--all", help="Convert every rule under rules/."),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Only emit this target (splunk|kusto)."
    ),
    check: bool = typer.Option(
        False, "--check", help="Exit non-zero if any rule fails to convert (CI gate)."
    ),
) -> None:
    """Convert Sigma rules to Splunk SPL and Microsoft Sentinel/Defender KQL."""
    if target is not None and target not in convert_mod.TARGETS:
        valid = ", ".join(convert_mod.TARGETS)
        console.print(f"[red]Unknown target '{target}'.[/red] Valid targets: {valid}.")
        raise typer.Exit(code=2)

    rule_paths = None if (all_rules or not paths) else list(paths)
    files = _discover_rules(rule_paths)
    if not files:
        console.print("[yellow]No rules found.[/yellow]")
        raise typer.Exit()

    failures = 0
    for f in files:
        console.rule(f"[bold cyan]{f.stem}")
        try:
            result = convert_mod.convert_file(f)
        except convert_mod.ConversionError as exc:
            failures += 1
            console.print(f"[red]conversion failed:[/red] {exc}")
            continue
        wanted = [target] if target else list(result.queries)
        for t in wanted:
            if t not in result.queries:
                console.print(f"[dim]{convert_mod.TARGET_LABELS.get(t, t)}: n/a for this rule[/dim]")
                continue
            tgt = convert_mod.TARGETS[t]
            console.print(f"[bold]{tgt.label}[/bold]")
            console.print(Syntax(result.query(t), tgt.lang, theme="ansi_dark", word_wrap=True))

    if check and failures:
        console.print(f"[red]{failures} rule(s) failed to convert.[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Converted {len(files)} rule(s) with {failures} failure(s).[/green]")


def _lazy_evaluate():
    from . import evaluate as evaluate_mod

    return evaluate_mod


@app.command()
def evaluate(
    paths: list[Path] | None = typer.Argument(None, help="Rule files/dirs (default: rules/)."),
    all_rules: bool = typer.Option(False, "--all", help="Fire-test every rule under rules/."),
) -> None:
    """Fire-test rules: positive sample logs must match, negatives must not."""
    evaluate_mod = _lazy_evaluate()
    rule_paths = None if (all_rules or not paths) else list(paths)
    files = _discover_rules(rule_paths)

    table = Table(title="Fire-test results")
    table.add_column("Rule", style="cyan")
    table.add_column("Positives", justify="right")
    table.add_column("Negatives", justify="right")
    table.add_column("Result")

    failures = 0
    for f in files:
        report = evaluate_mod.fire_test(f)
        if report.skipped:
            table.add_row(f.stem, "-", "-", "[yellow]no fixtures[/yellow]")
            continue
        ok = report.passed
        failures += 0 if ok else 1
        verdict = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(
            f.stem,
            f"{report.positives_matched}/{report.positives_total}",
            f"{report.negatives_clean}/{report.negatives_total}",
            verdict,
        )
    console.print(table)
    if failures:
        raise typer.Exit(code=1)


@app.command()
def coverage(
    layer: Path = typer.Option(Path("docs/attack-layer.json"), help="Navigator layer JSON output."),
    png: Path = typer.Option(Path("docs/images/attack-layer.png"), help="Heatmap PNG output."),
    site: Path | None = typer.Option(
        None, "--site", help="Also build a static coverage site (index.html + PNG + layer) in this dir."
    ),
) -> None:
    """Emit an ATT&CK Navigator layer and render the static heatmap PNG."""
    from . import coverage as coverage_mod

    if site is not None:
        summary = coverage_mod.build_site(site)
        console.print(f"[green]Built coverage site in {site}[/green].")
    else:
        summary = coverage_mod.build_coverage(layer_path=layer, png_path=png)
        console.print(
            f"[green]Wrote {layer}[/green] ({summary.attack_technique_count} ATT&CK techniques) "
            f"and [green]{png}[/green]."
        )
    if summary.atlas_technique_count:
        console.print(
            f"[cyan]ATLAS coverage:[/cyan] {summary.atlas_technique_count} technique(s) "
            "across the AI/LLM pack."
        )


@app.command()
def draft(
    threat: str = typer.Argument(..., help="Plain-English threat sentence to draft a rule for."),
    out: Path | None = typer.Option(None, "--out", help="Write the rule here if it validates."),
) -> None:
    """Draft a rule with a LOCAL LLM, then lint -> convert -> fire-test before accepting it."""
    from . import draft as draft_mod

    result = draft_mod.draft_rule(threat)
    console.print(Syntax(result.rule_yaml, "yaml", theme="ansi_dark"))
    if result.accepted:
        console.print("[bold green]ACCEPTED[/bold green] — passed lint, conversion, and fire-test.")
        if out:
            out.write_text(result.rule_yaml, encoding="utf-8")
            console.print(f"[green]Wrote {out}[/green]")
    else:
        console.print("[bold red]REJECTED[/bold red] — rule did not pass validation:")
        for stage, err in result.errors:
            console.print(f"  [red]{stage}[/red]: {err}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
