"""`python -m redteam ...` / `redteam ...` command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml
from rich import print as rprint

from redteam import report as report_mod
from redteam import runner
from redteam.schemas import CampaignReport
from redteam.target import build_target

app = typer.Typer(add_completion=False, help="Break the Bot — LLM red-team framework.")


@app.command()
def run(config: str = "configs/campaign.yaml", out: str = "findings") -> None:
    """Run the attack campaign against the configured target."""
    cfg = yaml.safe_load(Path(config).read_text())
    target = build_target(cfg)          # TODO(you): implement target.send()
    report = runner.run_campaign(config, target)
    Path(out).mkdir(parents=True, exist_ok=True)
    (Path(out) / "findings.json").write_text(report.model_dump_json(indent=2))
    rprint(f"[green]✓[/green] {report.total_attacks} attacks, "
           f"{len(report.findings)} findings -> {out}/findings.json")


@app.command()
def report(findings: str = "findings", out: str = "report") -> None:
    """Generate the pentest-style vulnerability report."""
    data = CampaignReport(**__import__("json").loads(
        (Path(findings) / "findings.json").read_text()))
    path = report_mod.write_report(data, out)
    rprint(f"[green]✓[/green] report at {path}")


@app.command()
def gate(findings: str = "findings", baseline: str = "baselines/blocked.json",
         fail_on: str = "high") -> None:
    """Fail (exit 1) on new high findings or a guardrail regression."""
    raise typer.Exit(code=report_mod.gate(findings, baseline, fail_on))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
