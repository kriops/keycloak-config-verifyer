# Keycloak Configuration Security Analyzer

**Static security analysis for Keycloak realm configurations against OAuth 2.0 and OpenID Connect best practices.**

Scan your Keycloak exports and identify security misconfigurations before they become vulnerabilities. Based on RFC 9700, OAuth 2.1, FAPI 2.0, and OWASP guidelines.

---

## Quick Start

### 1. Install

```bash
# Clone and install
git clone https://github.com/kriops/keycloak-config-verifyer.git
cd keycloak-config-verifyer
uv venv
uv pip install -e ".[dev]"
```

### 2. Run Analysis

```bash
# Analyze your realm exports (uv automatically uses the venv)
uv run keycloak-analyzer ./path/to/keycloak-configs

# Or activate venv and run directly
source .venv/bin/activate  # Linux/Mac
keycloak-analyzer ./path/to/keycloak-configs

# Generate HTML report
uv run keycloak-analyzer ./path/to/keycloak-configs --format html --output report.html

# CI/CD integration (JSON output)
uv run keycloak-analyzer ./path/to/keycloak-configs --format json --output report.json --quiet
```

### 3. Review Results

Open `report.html` in your browser or review the color-coded console output.

---

## What It Checks

✅ **PKCE enforcement** - Prevents authorization code interception
✅ **Redirect URI validation** - No wildcards, exact matching (RFC 9700)
✅ **Token security** - Lifespans, rotation, sender-constraining
✅ **Deprecated flows** - Detects implicit grant, password grant
✅ **Transport security** - SSL/TLS requirements
✅ **Client authentication** - Confidential client configurations

**24+ security checks** covering Critical to Info severity levels.
→ [Complete check reference](docs/check-reference.md)

---

## Features

🎯 **Actionable remediation** - Step-by-step fixes with Keycloak Admin Console navigation
📊 **Multiple formats** - Console, JSON, HTML with interactive filtering
🔍 **Flexible grouping** - Organize by severity, realm, or client
🚀 **CI/CD ready** - Exit codes, quiet mode, JSON output
📚 **RFC-backed** - Every finding references relevant standards (RFC 9700, OAuth 2.1, FAPI 2.0)

---

## Common Use Cases

**Security Audit:**
```bash
uv run keycloak-analyzer ./configs --format html --output security-audit.html
```

**Show Only Critical Issues:**
```bash
uv run keycloak-analyzer ./configs --severity critical
```

**Group by Client:**
```bash
uv run keycloak-analyzer ./configs --group-by client
```

**CI/CD Pipeline:**
```bash
# Fails if Critical/High findings exist
uv run keycloak-analyzer ./configs --format json --output report.json --quiet
```

**Development Workflow:**
```bash
# Run tests
uv run pytest

# Type check and lint
uv run mypy src/
uv run ruff check src/

# Format code
uv run black src/ tests/
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/usage-guide.md) | Command-line options, workflows, examples |
| [Check Reference](docs/check-reference.md) | Complete list of 24+ security checks |
| [Report Formats](docs/reports.md) | Details on Console, JSON, and HTML outputs |
| [Development Guide](AGENTS.md) | Contributing, adding checks, architecture |

---

## Standards & Compliance

This tool enforces security based on:

- **[RFC 9700](https://datatracker.ietf.org/doc/rfc9700/)** - OAuth 2.0 Security Best Current Practice
- **[RFC 7636](https://datatracker.ietf.org/doc/rfc7636/)** - Proof Key for Code Exchange (PKCE)
- **[OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)** - Modern OAuth security requirements
- **[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)** - Authentication layer
- **[FAPI 2.0](https://openid.net/specs/fapi-2_0-security-profile.html)** - Financial-grade API security
- **[OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)**

---

## Requirements

- **Python** 3.9+ (tested with 3.14)
- **Keycloak** 23.x - 26.x (realm export format)
- **uv** for package management ([Install uv](https://github.com/astral-sh/uv))

---

## Quick Links

- 📖 [Full Documentation](docs/usage-guide.md)
- 🐛 [Report Issues](https://github.com/kriops/keycloak-config-verifyer/issues)
- 🔒 [Security Policy](docs/security.md)
- 📧 [Contact](mailto:hello@kristofferopsahl.com)
- ⭐ [Star on GitHub](https://github.com/kriops/keycloak-config-verifyer)

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! See [Development Guide](AGENTS.md) for setup and guidelines.

---

**Built with ❤️ for the Keycloak and OAuth security community**
