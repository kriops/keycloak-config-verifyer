# Keycloak Configuration Security Analyzer

A Python CLI tool that performs static security analysis of Keycloak realm configurations against OAuth 2.0 and OpenID Connect security best practices from RFC 9700.

## Overview

This tool scans Keycloak realm export files (JSON) and identifies security misconfigurations based on:
- **RFC 9700** - OAuth 2.0 Security Best Current Practice (BCP 240)
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **OAuth 2.1** - Modern OAuth security requirements
- **OpenID Connect Core 1.0** - Authentication layer security
- **FAPI 2.0** - Financial-grade API security profile

## Features

- **Comprehensive Security Checks**: Critical to informational findings across multiple categories:
  - PKCE enforcement (RFC 9700 §3.1)
  - Redirect URI validation (exact matching, no wildcards)
  - Deprecated flow detection (implicit grant, password grant)
  - Transport security (TLS/SSL requirements)
  - Token security (lifespans, rotation, scoping)
  - Client authentication methods

- **Multiple Output Formats**:
  - **Console**: Rich, colored terminal output with severity badges
  - **JSON**: Machine-readable format for CI/CD integration
  - **HTML**: Interactive report with JavaScript filtering

- **Actionable Remediation**: Step-by-step fix instructions with Keycloak Admin Console navigation
- **RFC References**: Every finding links to relevant RFCs, CVEs, and security research

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd met-keycloak-config-verifyer

# Install with development dependencies
pip install -e ".[dev]"

# Or install for production use only
pip install .
```

## Quick Start

```bash
# Analyze Keycloak realm configurations in a directory
keycloak-analyzer ./keycloak-configs

# Generate HTML report
keycloak-analyzer ./keycloak-configs --format html --output report.html

# Generate JSON report for CI/CD
keycloak-analyzer ./keycloak-configs --format json --output report.json

# Filter by severity (only show Critical and High)
keycloak-analyzer ./keycloak-configs --severity high
```

## Usage

### Command Line Interface

```bash
keycloak-analyzer <path> [OPTIONS]

Arguments:
  path  Directory containing Keycloak realm export files

Options:
  -f, --format [console|json|html|all]  Output format (default: console)
  -o, --output PATH                     Output file path (required for json/html)
  -s, --severity [critical|high|medium|low|info]  Minimum severity to report
  --no-fail                             Always exit with code 0
  -q, --quiet                           Suppress console output
  --help                                Show this message and exit
```

### Examples

**Basic analysis with console output:**
```bash
keycloak-analyzer ./keycloak-configs
```

**Generate all report formats:**
```bash
keycloak-analyzer ./keycloak-configs --format all --output report
# Creates: console output + report.json + report.html
```

**CI/CD integration:**
```bash
keycloak-analyzer ./keycloak-configs --format json --output report.json --quiet
# Exit code 1 if Critical/High findings exist
# Exit code 0 if only Medium/Low/Info findings
```

### Exit Codes

- `0`: Success, no Critical or High severity findings
- `1`: Critical or High severity findings detected, or error occurred
- Use `--no-fail` to always exit with code 0 (useful for auditing without blocking)

## Security Checks

The analyzer implements 17+ security checks across multiple categories:

### Critical Severity
- **KC-PKCE-001**: PKCE not enforced for public clients
- **KC-PKCE-002**: PKCE using weak 'plain' method (not S256)
- **KC-FLOW-001**: Implicit grant enabled (deprecated, insecure)
- **KC-FLOW-003**: Password grant enabled (credentials exposed to client)
- **KC-REDIR-001**: Wildcard redirect URIs (enables subdomain takeover)

### High Severity
- **KC-REDIR-002**: HTTP redirect URIs (non-localhost)
- **KC-TLS-001**: SSL not required
- **KC-TOKEN-001**: Excessive access token lifespan
- **KC-TOKEN-002**: Refresh token reuse allowed (no rotation)

### Medium Severity
- **KC-PKCE-003**: PKCE optional for confidential clients
- **KC-TOKEN-003**: Full scope allowed (no least-privilege)
- **KC-AUTH-001**: Confidential client without authentication
- **KC-AUTH-002**: Using symmetric client secrets (recommend asymmetric)

### Low/Info Severity
- **KC-SEC-001**: Brute force protection disabled
- **KC-INFO-001**: Client secrets in export files
- **KC-BP-001**: Missing client descriptions

See `docs/check-reference.md` for complete check documentation.

## File Discovery

The tool automatically discovers Keycloak realm export files by scanning recursively for:
- `realm-export.json`
- `*-realm.json` (e.g., `production-realm.json`)

Both single-realm and multi-realm export formats are supported.

## Report Formats

### Console Output
Rich terminal output with:
- Color-coded severity badges (Critical = Red, High = Orange, etc.)
- Summary table showing finding counts by severity
- Detailed cards for each finding with description and remediation
- RFC/CVE references

### JSON Output
Machine-readable format with:
- Metadata (timestamp, analyzer version, standards)
- Summary statistics (counts by severity, category, client)
- Array of findings with all details
- Evidence objects for programmatic analysis

### HTML Output
Interactive web report with:
- Executive summary dashboard
- JavaScript-based filtering by severity
- Sortable findings table
- Color-coded severity badges
- Responsive design (mobile-friendly)
- Expandable finding details

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov

# Type checking
mypy src/

# Linting
ruff check src/

# Code formatting
black src/ tests/
```

### Project Structure

```
met-keycloak-config-verifyer/
├── src/keycloak_analyzer/
│   ├── core/           # File discovery, loading, analysis orchestration
│   ├── models/         # Pydantic models (Realm, Client, Finding)
│   ├── checks/         # Security check implementations
│   ├── reports/        # Report generators (Console, JSON, HTML)
│   └── cli.py          # Click CLI entry point
├── tests/
│   ├── fixtures/       # Sample Keycloak realm exports
│   ├── unit/           # Unit tests for each module
│   └── integration/    # End-to-end integration tests
└── docs/               # Additional documentation
```

### Adding New Checks

See `docs/adding-checks.md` for a guide on implementing custom security checks.

## Target Keycloak Version

- Primary: Keycloak 26.x
- Compatible: Keycloak 23.x - 26.x (realm export format)

## Standards & References

**Core Standards:**
- [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/rfc9700/)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/rfc7636/)
- [OAuth 2.1 (Draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)

**Security Research:**
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- CVE-2023-6927 - Keycloak redirect URI bypass
- CVE-2023-28131 - Expo PKCE bypass
- CVE-2024-10318 - NGINX OIDC nonce validation

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.

## Security Reporting

If you discover a security vulnerability in this tool, please email security@example.com

## Acknowledgments

Based on security best practices from:
- IETF OAuth Working Group
- OpenID Foundation
- OWASP Foundation
- Keycloak Community
