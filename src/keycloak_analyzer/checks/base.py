"""Base classes and registry for security checks."""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Type
import logging

from ..models import Finding, Severity, FindingCategory, ClientConfig, RealmConfig

logger = logging.getLogger(__name__)


class SecurityCheck(ABC):
    """
    Base class for all security checks.

    Each check should:
    1. Inherit from this class
    2. Set class attributes (check_id, check_name, etc.)
    3. Implement check_realm() and/or check_client()
    4. Use create_finding() helper for consistency
    """

    # Metadata (override in subclasses)
    check_id: str = ""  # e.g., "KC-PKCE-001"
    check_name: str = ""  # e.g., "PKCE Not Enforced"
    category: FindingCategory = FindingCategory.MISC
    default_severity: Severity = Severity.MEDIUM
    references: List[str] = []  # RFC/CVE references

    def check_realm(self, realm: RealmConfig) -> List[Finding]:
        """
        Check realm-level configuration.

        Args:
            realm: RealmConfig object

        Returns:
            List of findings (empty if no issues)
        """
        return []

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> List[Finding]:
        """
        Check individual client configuration.

        Args:
            client: ClientConfig object
            realm: Parent RealmConfig (for context)

        Returns:
            List of findings (empty if no issues)
        """
        return []

    def create_finding(
        self,
        title: str,
        description: str,
        remediation: str,
        realm: RealmConfig,
        client: Optional[ClientConfig] = None,
        severity: Optional[Severity] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Helper to create consistent findings.

        Args:
            title: Short summary of the issue
            description: Detailed explanation
            remediation: Step-by-step fix instructions
            realm: RealmConfig object
            client: ClientConfig if client-specific
            severity: Override default severity
            evidence: Supporting data

        Returns:
            Finding object
        """
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=severity or self.default_severity,
            category=self.category,
            realm_name=realm.realm,
            client_id=client.clientId if client else None,
            file_path=realm.file_path or "unknown",
            title=title,
            description=description,
            remediation=remediation,
            evidence=evidence or {},
            references=self.references,
        )

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return f"{self.__class__.__name__}(check_id='{self.check_id}')"


class CheckRegistry:
    """
    Registry for auto-discovering and managing security checks.

    Checks register themselves using the @security_check decorator.
    """

    _checks: List[Type[SecurityCheck]] = []

    @classmethod
    def register(cls, check_class: Type[SecurityCheck]) -> Type[SecurityCheck]:
        """
        Register a check class.

        Args:
            check_class: SecurityCheck subclass to register.

        Returns:
            The same check class (for decorator chaining).
        """
        if check_class not in cls._checks:
            cls._checks.append(check_class)
            logger.debug(
                f"Registered security check: {check_class.__name__} "
                f"(ID: {check_class.check_id or 'undefined'})"
            )
        return check_class

    @classmethod
    def get_all_checks(cls) -> List[SecurityCheck]:
        """
        Get instances of all registered checks.

        Returns:
            List of instantiated SecurityCheck objects.
        """
        return [check_class() for check_class in cls._checks]

    @classmethod
    def get_check_by_id(cls, check_id: str) -> Optional[SecurityCheck]:
        """
        Get a specific check by ID.

        Args:
            check_id: Check ID to search for.

        Returns:
            SecurityCheck instance if found, None otherwise.
        """
        for check_class in cls._checks:
            if check_class.check_id == check_id:
                return check_class()
        return None

    @classmethod
    def get_checks_by_category(cls, category: FindingCategory) -> List[SecurityCheck]:
        """
        Get all checks for a specific category.

        Args:
            category: FindingCategory to filter by.

        Returns:
            List of SecurityCheck instances matching the category.
        """
        return [
            check_class()
            for check_class in cls._checks
            if check_class.category == category
        ]

    @classmethod
    def get_checks_by_severity(cls, severity: Severity) -> List[SecurityCheck]:
        """
        Get all checks with a specific default severity.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of SecurityCheck instances matching the severity.
        """
        return [
            check_class()
            for check_class in cls._checks
            if check_class.default_severity == severity
        ]

    @classmethod
    def count(cls) -> int:
        """
        Get count of registered checks.

        Returns:
            Number of registered checks.
        """
        return len(cls._checks)

    @classmethod
    def clear(cls) -> None:
        """Clear registry (useful for testing)."""
        cls._checks = []
        logger.debug("Cleared check registry")

    @classmethod
    def list_all(cls) -> List[Dict[str, Any]]:
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
                "class_name": check.__class__.__name__,
            }
            for check in cls._checks
        ]


def security_check(cls: Type[SecurityCheck]) -> Type[SecurityCheck]:
    """
    Decorator to register a security check.

    Usage:
        @security_check
        class MyCheck(SecurityCheck):
            check_id = "KC-TEST-001"
            ...
    """
    CheckRegistry.register(cls)
    return cls
