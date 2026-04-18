import sys
import click
from .config import Config
from .scanner import Scanner
from .output.reporter import Reporter
from .cache.manager import CacheManager


@click.group()
@click.version_option(package_name="secure-req-check")
def main():
    """Secure Requirements Checker - Scan requirements.txt for known vulnerabilities using NVD API."""
    pass


@main.command()
@click.option(
    "-f", "--file",
    "requirements_file",
    type=click.Path(exists=True, dir_okay=False),
    default="requirements.txt",
    help="Path to requirements.txt file (default: ./requirements.txt)",
)
@click.option(
    "-o", "--output",
    "output_format",
    type=click.Choice(["table", "json", "csv", "quiet"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False, writable=True),
    help="Save report to file",
)
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    help="Minimum severity level to display",
)
@click.option(
    "--ignore-cve",
    multiple=True,
    help="Ignore specific CVE IDs (can be used multiple times)",
)
@click.option(
    "--ignore-package",
    multiple=True,
    help="Ignore specific package names (can be used multiple times)",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Disable cache (force fresh API requests)",
)
@click.option(
    "--timeout",
    type=int,
    default=30,
    help="API request timeout in seconds (default: 30)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Verbose output during scanning",
)
def scan(
    requirements_file,
    output_format,
    output_file,
    severity,
    ignore_cve,
    ignore_package,
    no_cache,
    timeout,
    verbose,
):
    """Scan a requirements.txt file for vulnerabilities."""
    config = Config()
    if timeout:
        config.request_timeout = timeout

    scanner = Scanner(
        config=config,
        use_cache=not no_cache,
        verbose=verbose,
    )

    try:
        vulnerabilities = scanner.scan_file(
            requirements_file,
            min_severity=severity.upper() if severity else None,
            ignore_cves=list(ignore_cve),
            ignore_packages=list(ignore_package),
        )
    except Exception as e:
        click.secho(f"Error during scan: {e}", fg="red", err=True)
        sys.exit(2)

    reporter = Reporter(output_format, output_file)
    reporter.generate(vulnerabilities, verbose=verbose)

    if vulnerabilities:
        severity_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "UNKNOWN": -1}
        highest_severity = max(
            (v.severity for v in vulnerabilities),
            key=lambda s: severity_levels.get(s, -1),
            default="LOW"
        )
        if severity and severity_levels.get(highest_severity, -1) >= severity_levels.get(severity.upper(), -1):
            sys.exit(1)
        sys.exit(1)
    sys.exit(0)


@main.group()
def config_cmd():
    """Manage configuration."""
    pass


@config_cmd.command("set-api-key")
@click.argument("key")
def set_api_key(key):
    """Store NVD API key."""
    config = Config()
    config.set_api_key(key)
    click.secho("API key saved successfully.", fg="green")


@config_cmd.command("clear-cache")
def clear_cache():
    """Clear local cache."""
    cache = CacheManager()
    cache.clear()
    click.secho("Cache cleared.", fg="green")


@config_cmd.command("show")
def show_config():
    """Show current configuration."""
    try:
        config = Config()
        api_key_display = "****" if config.api_key else "Not set"
        click.echo(f"API Key: {api_key_display}")
        click.echo(f"Cache directory: {config.cache_dir}")
        click.echo(f"Request timeout: {config.request_timeout}s")
    except Exception as e:
        click.secho(f"Error reading configuration: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()