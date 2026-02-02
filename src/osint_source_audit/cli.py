from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .audit import AuditRunner, write_report
from .config import AuditConfig

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


@app.command()
def audit(
    config_path: Path = typer.Option(..., "--config", "-c", exists=True, readable=True),
    output_dir: Path = typer.Option(Path("reports"), "--output", "-o"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent"),
) -> None:
    """Audit OSINT sources described in a YAML configuration file."""
    try:
        config = AuditConfig.from_yaml(config_path)
    except ValueError as exc:
        typer.echo(f"Configuration error: {exc}")
        raise typer.Exit(code=1) from exc

    runner = AuditRunner(
        config,
        timeout_seconds=timeout,
        user_agent=user_agent or "osint-source-audit",
    )
    report = runner.run()
    json_path, md_path = write_report(report, output_dir)

    table = Table(title="Audit Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Total sources", str(report.summary.total_sources))
    table.add_row("Successful", str(report.summary.successful))
    table.add_row("Failed", str(report.summary.failed))
    table.add_row("Schema valid", str(report.summary.schema_valid))

    console.print(table)
    console.print(f"Report saved: {json_path}")
    console.print(f"Markdown saved: {md_path}")
