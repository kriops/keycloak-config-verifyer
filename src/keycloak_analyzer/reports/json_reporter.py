"""JSON reporter for programmatic consumption."""

import json
from datetime import datetime
from typing import List, Dict

from .base import Reporter, ReportSummary
from ..models import Finding


class JSONReporter(Reporter):
    """JSON output for programmatic consumption and CI/CD integration."""

    def generate(
        self, findings: List[Finding], summary: ReportSummary, group_by: str = "severity"
    ) -> str:
        """
        Generate JSON report.

        Args:
            findings: List of findings to report.
            summary: Summary statistics.
            group_by: Grouping mode - "severity", "realm", or "client".

        Returns:
            JSON string with complete report data.
        """
        from ..utils import group_by_severity, group_by_realm, group_by_client

        output = {
            "metadata": {
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "analyzer_version": "0.1.0",
                "grouping_mode": group_by,
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
        }

        # Add grouped findings based on group_by mode
        if group_by == "client":
            grouped = group_by_client(findings)
            output["grouped_findings"] = self._client_groups_to_dict(grouped)
            output["grouping_note"] = (
                "Findings grouped by realm then client. "
                "Realm-level findings (without client_id) are excluded."
            )
        elif group_by == "realm":
            grouped = group_by_realm(findings)
            output["grouped_findings"] = {
                realm: [self._finding_to_dict(f) for f in realm_findings]
                for realm, realm_findings in grouped.items()
            }
        elif group_by == "severity":
            grouped = group_by_severity(findings)
            output["grouped_findings"] = {
                severity.value: [self._finding_to_dict(f) for f in sev_findings]
                for severity, sev_findings in grouped.items()
            }

        # Always include flat list for backward compatibility
        output["findings"] = [self._finding_to_dict(f) for f in findings]

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

    def _client_groups_to_dict(
        self, groups: Dict[str, Dict[str, List[Finding]]]
    ) -> Dict[str, Dict[str, list]]:
        """
        Convert nested client groups to JSON-serializable dict.

        Args:
            groups: Nested dictionary from group_by_client().

        Returns:
            JSON-serializable nested dictionary.
        """
        result = {}
        for realm_name, clients in groups.items():
            result[realm_name] = {}
            for client_id, client_findings in clients.items():
                result[realm_name][client_id] = [
                    self._finding_to_dict(f) for f in client_findings
                ]
        return result
