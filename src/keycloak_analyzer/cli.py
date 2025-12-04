"""CLI interface for Keycloak analyzer."""

import logging
import sys
from pathlib import Path
from typing import Optional

import click

from .core import RealmDiscovery, RealmLoader, RealmLoadError, SecurityAnalyzer
from .models import Severity
from .reports import ConsoleReporter, HTMLReporter, JSONReporter, ReportSummary

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["console", "json", "html", "all"], case_sensitive=False),
    default="console",
    help="Output format (default: console)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path (required for json/html)")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    help="Minimum severity level to report",
)
@click.option(
    "--no-fail",
    is_flag=True,
    help="Always exit with code 0 (ignore Critical/High findings)",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress console output")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option(
    "--group-by",
    "-g",
    type=click.Choice(["severity", "realm", "client"], case_sensitive=False),
    default="severity",
    help="Group findings by severity (default), realm, or client",
)
def analyze(
    path: str,
    format: str,
    output: Optional[str],
    severity: Optional[str],
    no_fail: bool,
    quiet: bool,
    verbose: bool,
    group_by: str,
):
    """
    Analyze Keycloak realm configurations for security issues.

    PATH: Directory containing Keycloak realm export files (*-realm.json, realm-export.json)

    \b
    Examples:
        keycloak-analyzer ./keycloak-configs
        keycloak-analyzer ./keycloak-configs --format json --output report.json
        keycloak-analyzer ./keycloak-configs --format html --output report.html
        keycloak-analyzer ./keycloak-configs --severity high --no-fail
        keycloak-analyzer ./keycloak-configs --group-by client
    """
    # Configure logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    try:
        # Step 1: Discover realm files
        if not quiet:
            click.echo("🔍 Scanning for Keycloak realm export files...")

        discovery = RealmDiscovery()
        realm_files = discovery.discover(Path(path))

        if not realm_files:
            click.echo("❌ No Keycloak realm export files found.", err=True)
            click.echo(f"   Searched for: {', '.join(discovery.REALM_PATTERNS)}", err=True)
            sys.exit(1)

        if not quiet:
            click.echo(f"✓ Found {len(realm_files)} realm file(s)")

        # Step 2: Load realm configurations
        if not quiet:
            click.echo("📖 Loading realm configurations...")

        loader = RealmLoader()
        realms = []
        for file_path in realm_files:
            try:
                realm_list = loader.load(file_path)
                realms.extend(realm_list)
                if verbose:
                    for realm in realm_list:
                        click.echo(
                            f"   Loaded realm '{realm.realm}' with {len(realm.clients)} client(s)"
                        )
            except RealmLoadError as e:
                click.echo(f"⚠️  Warning: Failed to load {file_path}: {e}", err=True)
                continue

        if not realms:
            click.echo("❌ No valid realm configurations loaded.", err=True)
            sys.exit(1)

        if not quiet:
            total_clients = sum(len(r.clients) for r in realms)
            click.echo(f"✓ Loaded {len(realms)} realm(s) with {total_clients} client(s)")

        # Step 3: Run security analysis
        if not quiet:
            click.echo("🔒 Running security analysis...")

        analyzer = SecurityAnalyzer()
        result = analyzer.analyze(realms)

        # Step 4: Filter by severity if specified
        findings = result.findings
        if severity:
            min_severity = Severity(severity.capitalize())
            severity_order = [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]
            min_index = severity_order.index(min_severity)
            findings = [f for f in findings if severity_order.index(f.severity) <= min_index]

        if not quiet:
            click.echo(f"✓ Analysis complete: {len(findings)} finding(s)")

        # Step 5: Generate reports
        summary = ReportSummary.from_findings(
            findings, result.realms_analyzed, result.clients_analyzed
        )

        if format == "console" or (format == "all" and not quiet):
            reporter = ConsoleReporter()
            reporter.generate(findings, summary, group_by=group_by)

        if format == "json" or format == "all":
            if not output:
                click.echo("❌ Error: --output required for JSON format", err=True)
                sys.exit(1)

            json_path = output if format == "json" else f"{output}.json"
            reporter = JSONReporter()
            content = reporter.generate(findings, summary, group_by=group_by)
            reporter.save(content, json_path)

            if not quiet:
                click.echo(f"✓ JSON report saved to: {json_path}")

        if format == "html" or format == "all":
            if not output:
                click.echo("❌ Error: --output required for HTML format", err=True)
                sys.exit(1)

            html_path = output if format == "html" else f"{output}.html"
            reporter = HTMLReporter()
            content = reporter.generate(findings, summary, group_by=group_by)
            reporter.save(content, html_path)

            if not quiet:
                click.echo(f"✓ HTML report saved to: {html_path}")

        # Step 6: Determine exit code
        if no_fail:
            exit_code = 0
        else:
            exit_code = summary.exit_code

        if not quiet and exit_code == 1:
            click.echo(
                "\n⚠️  Critical or High severity findings detected. Exit code: 1",
                err=True,
            )
        elif not quiet and exit_code == 0 and len(findings) > 0:
            click.echo("\n✓ No Critical/High findings. Exit code: 0")

        sys.exit(exit_code)

    except click.Abort:
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n\nInterrupted by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    analyze()
