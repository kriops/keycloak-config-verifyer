"""Console reporter with Rich formatting."""

from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .base import Reporter, ReportSummary
from ..models import Finding, Severity


class ConsoleReporter(Reporter):
    """Terminal output with Rich formatting."""

    def __init__(self):
        """Initialize console reporter."""
        self.console = Console()

    def generate(
        self, findings: List[Finding], summary: ReportSummary, group_by: str = "severity"
    ) -> str:
        """
        Generate console output (prints directly, returns empty string).

        Args:
            findings: List of findings to report.
            summary: Summary statistics.
            group_by: Grouping mode - "severity" (default), "realm", or "client".

        Returns:
            Empty string (output is printed directly to console).
        """
        from ..utils import group_by_severity, group_by_realm, group_by_client

        self._print_header()
        self._print_summary(summary)

        if group_by == "client":
            # Hierarchical grouping: Realm → Client → Findings
            grouped = group_by_client(findings)

            if not grouped:
                self.console.print("\n[yellow]ℹ️  No client-level findings to display.[/yellow]")
                self.console.print("[dim]Use --group-by severity or --group-by realm to see realm-level findings.[/dim]\n")
            else:
                for realm_name in grouped:
                    self._print_client_grouped_realm_section(realm_name, grouped[realm_name])

        elif group_by == "realm":
            # Group by realm, then by severity within each realm
            grouped = group_by_realm(findings)
            for realm_name in grouped:
                realm_findings = grouped[realm_name]
                self._print_realm_section(realm_name, realm_findings)

        else:  # group_by == "severity" (default)
            # Group findings by severity
            grouped = group_by_severity(findings)
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                if severity in grouped:
                    self._print_severity_section(severity, grouped[severity])

        self._print_footer(summary)
        return ""  # Console prints directly

    def save(self, content: str, output_path: str) -> None:
        """Console reporter doesn't save to file."""
        pass

    def _print_header(self) -> None:
        """Print report header."""
        self.console.print("\n")
        self.console.print(
            Panel.fit(
                "[bold cyan]🔒 Keycloak Security Analysis Report[/bold cyan]",
                box=box.DOUBLE,
            )
        )
        self.console.print()

    def _print_summary(self, summary: ReportSummary) -> None:
        """Print summary statistics."""
        table = Table(title="Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", style="bold", justify="right")

        table.add_row("Realms Analyzed", str(summary.realms_analyzed))
        table.add_row("Clients Analyzed", str(summary.clients_analyzed))
        table.add_row("Total Findings", str(summary.total_findings))

        # Severity breakdown with colors
        for severity, count in summary.by_severity.items():
            if count > 0:
                color = self.severity_color_code(severity)
                table.add_row(
                    f"[{color}]{severity.value}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                )

        self.console.print(table)
        self.console.print()

    def _print_realm_section(self, realm_name: str, findings: List[Finding]) -> None:
        """Print a section for a specific realm."""
        self.console.print(f"\n[bold cyan]🏰 REALM: {realm_name} ({len(findings)} findings)[/bold cyan]")
        self.console.print("═" * 80)

        # Group findings within realm by severity
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            severity_findings = [f for f in findings if f.severity == severity]
            if severity_findings:
                color = self.severity_color_code(severity)
                icon = self._severity_icon(severity)
                self.console.print(
                    f"\n[{color}]{icon} {severity.value} ({len(severity_findings)})[/{color}]"
                )
                self.console.print("─" * 80)

                for i, finding in enumerate(severity_findings, 1):
                    self._print_finding(finding, color, i)

    def _print_severity_section(
        self, severity: Severity, findings: List[Finding]
    ) -> None:
        """Print a section for a specific severity level."""
        color = self.severity_color_code(severity)
        icon = self._severity_icon(severity)

        self.console.print(
            f"\n[bold {color}]{icon} {severity.value.upper()} FINDINGS ({len(findings)})[/bold {color}]"
        )
        self.console.print("─" * 80)

        for i, finding in enumerate(findings, 1):
            self._print_finding(finding, color, i)

    def _print_finding(self, finding: Finding, color: str, number: int) -> None:
        """Print a single finding."""
        self.console.print(f"\n[bold {color}]{number}. [{finding.check_id}] {finding.title}[/bold {color}]")

        # Metadata
        meta_parts = [f"Realm: {finding.realm_name}"]
        if finding.client_id:
            meta_parts.append(f"Client: [cyan]{finding.client_id}[/cyan]")
        meta_parts.append(f"File: {finding.file_path}")
        self.console.print("   " + " | ".join(meta_parts))

        # Description (truncate if very long)
        desc_lines = finding.description.split("\n")
        if len(desc_lines) > 10:
            # Show first 8 lines + indication of more
            for line in desc_lines[:8]:
                if line.strip():
                    self.console.print(f"   {line}")
            self.console.print(f"   [dim]... ({len(desc_lines) - 8} more lines)[/dim]")
        else:
            for line in desc_lines:
                if line.strip():
                    self.console.print(f"   {line}")

        # Remediation (show first few steps)
        self.console.print(f"\n   [bold]🔧 Remediation:[/bold]")
        remediation_lines = finding.remediation.split("\n")
        shown_lines = 0
        for line in remediation_lines:
            if line.strip() and shown_lines < 6:
                self.console.print(f"   {line}")
                shown_lines += 1
            elif shown_lines >= 6:
                self.console.print(f"   [dim]... (see full report for details)[/dim]")
                break

        # References
        if finding.references:
            refs = ", ".join(finding.references[:3])
            if len(finding.references) > 3:
                refs += f", +{len(finding.references) - 3} more"
            self.console.print(f"\n   [dim]References: {refs}[/dim]")

    def _print_footer(self, summary: ReportSummary) -> None:
        """Print report footer."""
        self.console.print("\n" + "═" * 80)

        if summary.exit_code == 1:
            self.console.print(
                f"[bold red]⚠  CRITICAL/HIGH findings present. "
                f"Exit code: {summary.exit_code}[/bold red]"
            )
            self.console.print(
                "[yellow]Action required: Address critical and high severity issues before deployment.[/yellow]"
            )
        else:
            self.console.print(
                f"[bold green]✓ No Critical/High findings. "
                f"Exit code: {summary.exit_code}[/bold green]"
            )
            if summary.total_findings > 0:
                self.console.print(
                    "[cyan]Review medium/low findings to further improve security posture.[/cyan]"
                )

        self.console.print()

    def _print_client_grouped_realm_section(
        self, realm_name: str, clients: Dict[str, List[Finding]]
    ) -> None:
        """Print a realm section with client grouping."""
        total_findings = sum(len(findings) for findings in clients.values())

        self.console.print(
            f"\n[bold cyan]🏰 REALM: {realm_name} "
            f"({len(clients)} clients, {total_findings} findings)[/bold cyan]"
        )
        self.console.print("═" * 80)

        for client_id in clients:
            client_findings = clients[client_id]
            self._print_client_section(client_id, client_findings)

    def _print_client_section(self, client_id: str, findings: List[Finding]) -> None:
        """Print a section for a specific client."""
        self.console.print(
            f"\n  [bold magenta]🔧 CLIENT: {client_id} ({len(findings)} findings)[/bold magenta]"
        )
        self.console.print("  " + "─" * 78)

        # Group findings within client by severity
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            severity_findings = [f for f in findings if f.severity == severity]
            if severity_findings:
                color = self.severity_color_code(severity)
                icon = self._severity_icon(severity)
                self.console.print(
                    f"\n    [{color}]{icon} {severity.value} ({len(severity_findings)})[/{color}]"
                )

                for i, finding in enumerate(severity_findings, 1):
                    self._print_finding_indented(finding, color, i, indent=4)

    def _print_finding_indented(
        self, finding: Finding, color: str, number: int, indent: int = 0
    ) -> None:
        """Print a single finding with custom indentation."""
        indent_str = " " * indent

        self.console.print(
            f"\n{indent_str}[bold {color}]{number}. [{finding.check_id}] {finding.title}[/bold {color}]"
        )

        # Metadata
        meta_parts = [f"Client: [cyan]{finding.client_id}[/cyan]"]
        meta_parts.append(f"File: {finding.file_path}")
        self.console.print(indent_str + "   " + " | ".join(meta_parts))

        # Description
        desc_lines = finding.description.split("\n")
        if len(desc_lines) > 10:
            for line in desc_lines[:8]:
                if line.strip():
                    self.console.print(f"{indent_str}   {line}")
            self.console.print(f"{indent_str}   [dim]... ({len(desc_lines) - 8} more lines)[/dim]")
        else:
            for line in desc_lines:
                if line.strip():
                    self.console.print(f"{indent_str}   {line}")

        # Remediation
        self.console.print(f"\n{indent_str}   [bold]🔧 Remediation:[/bold]")
        remediation_lines = finding.remediation.split("\n")
        shown_lines = 0
        for line in remediation_lines:
            if line.strip() and shown_lines < 6:
                self.console.print(f"{indent_str}   {line}")
                shown_lines += 1
            elif shown_lines >= 6:
                self.console.print(f"{indent_str}   [dim]... (see full report for details)[/dim]")
                break

        # References
        if finding.references:
            refs = ", ".join(finding.references[:3])
            if len(finding.references) > 3:
                refs += f", +{len(finding.references) - 3} more"
            self.console.print(f"\n{indent_str}   [dim]References: {refs}[/dim]")

    def _severity_icon(self, severity: Severity) -> str:
        """Get emoji icon for severity."""
        icons = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "⚠️ ",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "ℹ️ ",
            Severity.INFO: "💡",
        }
        return icons.get(severity, "•")
