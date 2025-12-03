"""Security analyzer orchestration."""

import logging
from typing import List
from dataclasses import dataclass

from ..models import RealmConfig, Finding, Severity
from ..checks import CheckRegistry

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Results from security analysis."""

    findings: List[Finding]
    realms_analyzed: int
    clients_analyzed: int
    checks_executed: int

    @property
    def critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        """Get all high severity findings."""
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> List[Finding]:
        """Get all medium severity findings."""
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> List[Finding]:
        """Get all low severity findings."""
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def info_findings(self) -> List[Finding]:
        """Get all info severity findings."""
        return [f for f in self.findings if f.severity == Severity.INFO]

    @property
    def has_critical_or_high(self) -> bool:
        """Check if there are any critical or high severity findings."""
        return len(self.critical_findings) > 0 or len(self.high_findings) > 0

    def get_exit_code(self) -> int:
        """
        Get exit code based on findings.

        Returns:
            1 if critical or high findings exist, 0 otherwise.
        """
        return 1 if self.has_critical_or_high else 0


class SecurityAnalyzer:
    """
    Orchestrates security checks across realm configurations.

    The analyzer:
    1. Gets all registered security checks
    2. Executes realm-level checks
    3. Executes client-level checks for each client
    4. Aggregates and returns all findings
    """

    def __init__(self):
        """Initialize the analyzer."""
        self.checks = CheckRegistry.get_all_checks()
        logger.info(f"Initialized analyzer with {len(self.checks)} security checks")

    def analyze(self, realms: List[RealmConfig]) -> AnalysisResult:
        """
        Analyze security of realm configurations.

        Args:
            realms: List of RealmConfig objects to analyze.

        Returns:
            AnalysisResult containing all findings and statistics.
        """
        logger.info(f"Starting security analysis of {len(realms)} realm(s)")

        all_findings: List[Finding] = []
        total_clients = 0

        for realm in realms:
            logger.debug(f"Analyzing realm: {realm.realm}")

            # Run realm-level checks
            realm_findings = self._analyze_realm(realm)
            all_findings.extend(realm_findings)

            logger.debug(
                f"Realm '{realm.realm}': {len(realm_findings)} realm-level finding(s)"
            )

            # Run client-level checks
            client_findings = self._analyze_clients(realm)
            all_findings.extend(client_findings)
            total_clients += len(realm.clients)

            logger.debug(
                f"Realm '{realm.realm}': {len(client_findings)} client-level finding(s) "
                f"across {len(realm.clients)} client(s)"
            )

        result = AnalysisResult(
            findings=all_findings,
            realms_analyzed=len(realms),
            clients_analyzed=total_clients,
            checks_executed=len(self.checks),
        )

        logger.info(
            f"Analysis complete: {len(all_findings)} total finding(s) "
            f"({len(result.critical_findings)} critical, "
            f"{len(result.high_findings)} high, "
            f"{len(result.medium_findings)} medium, "
            f"{len(result.low_findings)} low, "
            f"{len(result.info_findings)} info)"
        )

        return result

    def _analyze_realm(self, realm: RealmConfig) -> List[Finding]:
        """
        Run realm-level security checks.

        Args:
            realm: RealmConfig to analyze.

        Returns:
            List of findings from realm-level checks.
        """
        findings: List[Finding] = []

        for check in self.checks:
            try:
                check_findings = check.check_realm(realm)
                findings.extend(check_findings)

                if check_findings:
                    logger.debug(
                        f"Check {check.check_id} found {len(check_findings)} "
                        f"issue(s) in realm '{realm.realm}'"
                    )

            except Exception as e:
                logger.error(
                    f"Error executing check {check.check_id} on realm '{realm.realm}': {e}",
                    exc_info=True,
                )
                continue

        return findings

    def _analyze_clients(self, realm: RealmConfig) -> List[Finding]:
        """
        Run client-level security checks for all clients in a realm.

        Args:
            realm: RealmConfig containing clients to analyze.

        Returns:
            List of findings from client-level checks.
        """
        findings: List[Finding] = []

        for client in realm.clients:
            logger.debug(f"Analyzing client: {client.clientId}")

            for check in self.checks:
                try:
                    check_findings = check.check_client(client, realm)
                    findings.extend(check_findings)

                    if check_findings:
                        logger.debug(
                            f"Check {check.check_id} found {len(check_findings)} "
                            f"issue(s) in client '{client.clientId}'"
                        )

                except Exception as e:
                    logger.error(
                        f"Error executing check {check.check_id} on client "
                        f"'{client.clientId}' in realm '{realm.realm}': {e}",
                        exc_info=True,
                    )
                    continue

        return findings

    def get_check_count(self) -> int:
        """
        Get the number of registered checks.

        Returns:
            Number of security checks available.
        """
        return len(self.checks)

    def list_checks(self) -> List[dict]:
        """
        Get metadata for all registered checks.

        Returns:
            List of dictionaries with check metadata.
        """
        return [
            {
                "check_id": check.check_id,
                "check_name": check.check_name,
                "category": check.category.value,
                "severity": check.default_severity.value,
            }
            for check in self.checks
        ]

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return f"SecurityAnalyzer(checks={len(self.checks)})"
