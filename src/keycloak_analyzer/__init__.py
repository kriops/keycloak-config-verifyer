"""Keycloak Configuration Security Analyzer.

A Python CLI tool that performs static security analysis of Keycloak realm
configurations against OAuth 2.0 and OpenID Connect security best practices
from RFC 9700.
"""

__version__ = "0.1.0"
__author__ = "Kristoffer Opsahl"
__license__ = "MIT"

from .core import RealmDiscovery, RealmLoader, SecurityAnalyzer, AnalysisResult
from .models import Finding, Severity, FindingCategory, ClientConfig, RealmConfig
from .checks import CheckRegistry, SecurityCheck
from .reports import ConsoleReporter, JSONReporter, HTMLReporter, ReportSummary

__all__ = [
    # Version
    "__version__",
    # Core
    "RealmDiscovery",
    "RealmLoader",
    "SecurityAnalyzer",
    "AnalysisResult",
    # Models
    "Finding",
    "Severity",
    "FindingCategory",
    "ClientConfig",
    "RealmConfig",
    # Checks
    "CheckRegistry",
    "SecurityCheck",
    # Reports
    "ConsoleReporter",
    "JSONReporter",
    "HTMLReporter",
    "ReportSummary",
]
