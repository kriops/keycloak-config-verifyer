"""JSON reporter for programmatic consumption."""

import json
from datetime import datetime
from typing import List

from .base import Reporter, ReportSummary
from ..models import Finding


class JSONReporter(Reporter):
    """JSON output for programmatic consumption and CI/CD integration."""

    def generate(self, findings: List[Finding], summary: ReportSummary) -> str:
        """
        Generate JSON report.

        Args:
            findings: List of findings to report.
            summary: Summary statistics.

        Returns:
            JSON string with complete report data.
        """
        output = {
            "metadata": {
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "analyzer_version": "0.1.0",
                "standards": [
                    "RFC 9700 - OAuth 2.0 Security BCP",
                    "RFC 7636 - PKCE",
                    "OAuth 2.1 (Draft)",
                    "OpenID Connect Core 1.0",
                ],
            },
            "summary": {
                "total_findings": summary.total_findings,
                "realms_analyzed": summary.realms_analyzed,
                "clients_analyzed": summary.clients_analyzed,
                "exit_code": summary.exit_code,
                "by_severity": {k.value: v for k, v in summary.by_severity.items()},
                "by_category": summary.by_category,
                "by_client": summary.by_client,
            },
            "findings": [self._finding_to_dict(f) for f in findings],
        }

        return json.dumps(output, indent=2, ensure_ascii=False)

    def save(self, content: str, output_path: str) -> None:
        """
        Save JSON to file.

        Args:
            content: JSON content to save.
            output_path: Path where JSON should be saved.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def _finding_to_dict(self, finding: Finding) -> dict:
        """
        Convert Finding to dictionary for JSON serialization.

        Args:
            finding: Finding object to convert.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "check_id": finding.check_id,
            "check_name": finding.check_name,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "realm_name": finding.realm_name,
            "client_id": finding.client_id,
            "file_path": finding.file_path,
            "title": finding.title,
            "description": finding.description,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "references": finding.references,
            "timestamp": finding.timestamp.isoformat(),
        }
