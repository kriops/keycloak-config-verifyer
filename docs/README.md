# Documentation Index

Complete documentation for the Keycloak Configuration Security Analyzer.

## Getting Started

**New to this tool?** Start here:

1. [Main README](../README.md) - Quick start, installation, overview
2. [Usage Guide](usage-guide.md) - Command-line options and workflows
3. [Report Formats](reports.md) - Understanding Console, JSON, and HTML outputs

## User Documentation

### Core Documentation

| Document | Description | When to Read |
|----------|-------------|--------------|
| [Usage Guide](usage-guide.md) | Complete CLI reference, examples, workflows | Before first use |
| [Check Reference](check-reference.md) | All 24+ security checks explained | Understanding findings |
| [Report Formats](reports.md) | Console, JSON, HTML format details | Choosing output format |

### Quick References

| Document | Description | When to Read |
|----------|-------------|--------------|
| [Security Policy](security.md) | Reporting vulnerabilities, best practices | Security concerns |

## Developer Documentation

**Contributing or extending the tool?**

| Document | Description | When to Read |
|----------|-------------|--------------|
| [AGENTS.md](../AGENTS.md) | Development guide for humans and AI agents | Before contributing |
| [CLAUDE.md](../CLAUDE.md) | Quick reference for AI coding assistants | AI agent setup |
| [Adding Checks](adding-checks.md) | Guide to implementing new security checks | Adding features |

## Security Standards

This tool enforces security based on:

- **[RFC 9700](https://datatracker.ietf.org/doc/rfc9700/)** - OAuth 2.0 Security Best Current Practice
- **[RFC 7636](https://datatracker.ietf.org/doc/rfc7636/)** - Proof Key for Code Exchange (PKCE)
- **[OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)** - Modern OAuth security
- **[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)** - Authentication layer
- **[FAPI 2.0](https://openid.net/specs/fapi-2_0-security-profile.html)** - Financial-grade API security
- **[OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)**

## Documentation by Task

### I want to...

**...quickly analyze my Keycloak config**
→ See [Quick Start](../README.md#quick-start)

**...understand a specific finding**
→ See [Check Reference](check-reference.md)

**...generate reports for stakeholders**
→ See [Report Formats](reports.md#html-output)

**...integrate with CI/CD**
→ See [Usage Guide - CI/CD Integration](usage-guide.md#cicd-integration)

**...add a new security check**
→ See [Adding Checks](adding-checks.md)

**...contribute code**
→ See [AGENTS.md](../AGENTS.md)

**...report a security issue**
→ See [Security Policy](security.md)

## Documentation by Audience

### 👤 End Users (Security Auditors)

1. [Quick Start](../README.md#quick-start)
2. [Usage Guide](usage-guide.md)
3. [Check Reference](check-reference.md)
4. [Report Formats](reports.md)

### 👨‍💻 Developers (Contributing)

1. [AGENTS.md](../AGENTS.md)
2. [Adding Checks](adding-checks.md)
3. [Security Policy](security.md)

### 🤖 AI Coding Assistants

1. [CLAUDE.md](../CLAUDE.md)
2. [AGENTS.md](../AGENTS.md)
3. [Usage Guide](usage-guide.md)

### 🏢 DevOps / CI/CD Engineers

1. [Usage Guide - CI/CD Integration](usage-guide.md#cicd-integration)
2. [Report Formats - JSON](reports.md#json-output)

## File Organization

```
met-keycloak-config-verifyer/
├── README.md                      # Quick start for new users
├── CLAUDE.md                      # AI agent quick reference
├── AGENTS.md                      # Comprehensive development guide
│
├── docs/
│   ├── README.md                  # This file (documentation index)
│   ├── usage-guide.md             # Complete CLI usage guide
│   ├── check-reference.md         # All security checks documented
│   ├── reports.md                 # Report format specifications
│   ├── security.md                # Security policy and reporting
│   └── adding-checks.md           # Guide for adding new checks
│
├── src/keycloak_analyzer/         # Source code
│   ├── checks/                    # Security check implementations
│   ├── models/                    # Data models
│   ├── reports/                   # Report generators
│   └── core/                      # Core logic
│
└── tests/                         # Test suite
    ├── unit/                      # Unit tests
    └── integration/               # Integration tests
```

## External Resources

### Keycloak Documentation

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Realm Export/Import](https://www.keycloak.org/server/importExport)
- [Client Configuration](https://www.keycloak.org/docs/latest/server_admin/#_clients)

### OAuth / OpenID Connect

- [OAuth 2.0 (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Security BCP (RFC 9700)](https://datatracker.ietf.org/doc/rfc9700/)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE (RFC 7636)](https://datatracker.ietf.org/doc/rfc7636/)

### Security Research

- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OAuth 2.0 Security Workshop](https://oauth.net/events/2023-security-workshop/)

## Getting Help

- 🐛 [Report Issues](https://github.com/kriops/keycloak-config-verifyer/issues)
- 💬 [Discussions](https://github.com/kriops/keycloak-config-verifyer/discussions)
- 📧 [Email Support](mailto:hello@kristofferopsahl.com)

---

**Need something not covered here?** [Open an issue](https://github.com/kriops/keycloak-config-verifyer/issues) to request documentation improvements!
