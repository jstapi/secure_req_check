# src/secure_req_check/output/reporter.py
import sys
from typing import List, Optional
import click
from ..models.vulnerability import Vulnerability
from .formatter import format_table, format_json, format_csv


class Reporter:
    def __init__(self, output_format: str, output_file: Optional[str] = None):
        self.output_format = output_format
        self.output_file = output_file

    def generate(self, vulnerabilities: List[Vulnerability], verbose: bool = False):
        if self.output_format == "quiet":
            return

        output = self._format(vulnerabilities)

        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(output)
            if verbose or self.output_format != "quiet":
                click.secho(f"Report saved to {self.output_file}", fg="green")
        else:
            click.echo(output)

            # Print summary only for table format and only to console
            if self.output_format == "table":
                self._print_summary(vulnerabilities)

    def _format(self, vulnerabilities: List[Vulnerability]) -> str:
        if self.output_format == "json":
            return format_json(vulnerabilities)
        elif self.output_format == "csv":
            return format_csv(vulnerabilities)
        else:  # table
            return format_table(vulnerabilities)

    def _print_summary(self, vulnerabilities: List[Vulnerability]):
        if not vulnerabilities:
            click.secho("\nNo vulnerabilities found.", fg="green")
            return

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1

        summary = ", ".join(f"{sev}: {cnt}" for sev, cnt in counts.items() if cnt > 0)
        click.secho(f"\nFound {len(vulnerabilities)} vulnerabilities ({summary})", fg="yellow")
        click.secho("Consider upgrading affected packages.", fg="blue")