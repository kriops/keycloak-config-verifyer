"""Base classes for report generation."""

from abc import ABC, abstractmethod
from typing import List, Dict
from dataclasses import dataclass

from ..models import Finding, Severity, FindingCategory


@dataclass
class ReportSummary:
    """Summary statistics for a report."""

    total_findings: int
    by_severity: Dict[Severity, int]
    by_category: Dict[str, int]
    by_client: Dict[str, int]
    realms_analyzed: int
    clients_analyzed: int
    exit_code: int

    @classmethod
    def from_findings(
        cls, findings: List[Finding], realms_analyzed: int, clients_analyzed: int
    ) -> "ReportSummary":
        """
        Create a summary from a list of findings.

        Args:
            findings: List of Finding objects.
            realms_analyzed: Number of realms analyzed.
            clients_analyzed: Number of clients analyzed.

        Returns:
            ReportSummary object with calculated statistics.
        """
        # Count by severity
        severity_counts = {s: 0 for s in Severity}
        for finding in findings:
            severity_counts[finding.severity] += 1

        # Count by category
        category_counts: Dict[str, int] = {}
        for finding in findings:
            category = finding.category.value
            category_counts[category] = category_counts.get(category, 0) + 1

        # Count by client
        client_counts: Dict[str, int] = {}
        for finding in findings:
            if finding.client_id:
                client_counts[finding.client_id] = (
                    client_counts.get(finding.client_id, 0) + 1
                )

        # Calculate exit code: 1 if Critical or High findings
        exit_code = (
            1
            if (
                severity_counts[Severity.CRITICAL] > 0
                or severity_counts[Severity.HIGH] > 0
            )
            else 0
        )

        return cls(
            total_findings=len(findings),
            by_severity=severity_counts,
            by_category=category_counts,
            by_client=client_counts,
            realms_analyzed=realms_analyzed,
            clients_analyzed=clients_analyzed,
            exit_code=exit_code,
        )


class Reporter(ABC):
    """Base class for all report formatters."""

    @abstractmethod
    def generate(
        self,
        findings: List[Finding],
        summary: ReportSummary,
        group_by: str = "severity",
    ) -> str:
        """
        Generate report content.

        Args:
            findings: List of Finding objects.
            summary: ReportSummary with statistics.
            group_by: Grouping mode - "severity" (default), "realm", or "client".

        Returns:
            Report content as string.
        """
        pass

    @abstractmethod
    def save(self, content: str, output_path: str) -> None:
        """
        Save report to file.

        Args:
            content: Report content to save.
            output_path: Path where report should be saved.
        """
        pass

    def severity_color_code(self, severity: Severity) -> str:
        """
        Get ANSI color code for severity.

        Args:
            severity: Severity level.

        Returns:
            Color name or ANSI code.
        """
        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "green",
        }
        return colors.get(severity, "white")

    def severity_html_color(self, severity: Severity) -> str:
        """
        Get HTML hex color for severity.

        Args:
            severity: Severity level.

        Returns:
            Hex color code.
        """
        colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#17a2b8",
            Severity.INFO: "#28a745",
        }
        return colors.get(severity, "#6c757d")
