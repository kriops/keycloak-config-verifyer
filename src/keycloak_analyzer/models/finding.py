"""Security finding models and enums."""

from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime


class Severity(str, Enum):
    """Security finding severity levels."""

    CRITICAL = "Critical"  # Immediate exploitation, RFC violation
    HIGH = "High"  # Serious weakness, likely exploitable
    MEDIUM = "Medium"  # Weakness requiring specific conditions
    LOW = "Low"  # Minor concern, defense-in-depth
    INFO = "Info"  # Informational, best practice


class FindingCategory(str, Enum):
    """Categories of security findings."""

    PKCE = "PKCE"
    REDIRECT_URI = "Redirect URI Validation"
    TOKEN_SECURITY = "Token Security"
    CLIENT_AUTH = "Client Authentication"
    OAUTH_FLOWS = "OAuth Flows"
    TRANSPORT = "Transport Security"
    MISC = "Miscellaneous"


class Finding(BaseModel):
    """Security finding from analysis."""

    # Check identification
    check_id: str  # e.g., "KC-PKCE-001"
    check_name: str  # e.g., "PKCE Not Enforced"
    severity: Severity
    category: FindingCategory

    # Location
    realm_name: str
    client_id: Optional[str] = None  # None for realm-level findings
    file_path: str

    # Description
    title: str  # Short summary
    description: str  # Detailed explanation of the issue
    remediation: str  # Step-by-step fix instructions

    # Supporting information
    evidence: Dict[str, Any] = Field(default_factory=dict)
    # Evidence contains actual config values that triggered the finding

    references: List[str] = Field(default_factory=list)
    # RFC references, CVE numbers, documentation links

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.now)

    class Config:
        use_enum_values = False  # Keep enum objects
        json_encoders = {datetime: lambda v: v.isoformat()}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "realm_name": self.realm_name,
            "client_id": self.client_id,
            "file_path": self.file_path,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
        }

    def __str__(self) -> str:
        """Human-readable string representation."""
        client_info = f" [{self.client_id}]" if self.client_id else ""
        return (
            f"[{self.severity.value}] {self.check_id}: {self.title}"
            f"{client_info} in {self.realm_name}"
        )

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"Finding(check_id='{self.check_id}', "
            f"severity={self.severity}, "
            f"realm='{self.realm_name}', "
            f"client={self.client_id})"
        )
