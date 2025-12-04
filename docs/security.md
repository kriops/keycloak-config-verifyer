# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in the Keycloak Configuration Security Analyzer, please report it responsibly.

### How to Report

1. **GitHub Security Advisory** (Preferred)
   - Go to [Security Advisories](https://github.com/kriops/keycloak-config-verifyer/security/advisories)
   - Click "Report a vulnerability"
   - Provide details about the vulnerability

2. **Email**
   - Send to: hello@kristofferopsahl.com
   - Use subject: "Security Vulnerability Report - Keycloak Analyzer"
   - Include details about the vulnerability

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)
- Your contact information

### Response Timeline

- **Initial response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium/Low: Next release cycle

### Disclosure Policy

- We will coordinate disclosure with you
- Security advisories published after fix is available
- Credit given to reporter (unless anonymity requested)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |
| < 0.1   | ❌ No     |

## Security Best Practices

### When Using This Tool

1. **Protect realm exports**
   - Realm export files contain sensitive data
   - Do not commit realm exports to public repositories
   - Use `.gitignore` to exclude exports (e.g., `excluded/` folder)

2. **Review reports carefully**
   - HTML/JSON reports may contain sensitive information
   - Client IDs, realm names, configuration details
   - Share reports securely (encrypted channels)

3. **CI/CD security**
   - Store reports as private artifacts
   - Limit access to CI/CD pipelines
   - Use `--quiet` mode to avoid console output leakage

### When Contributing

1. **Code review**
   - All contributions require review
   - Security-focused checks for new code
   - Testing for potential vulnerabilities

2. **Dependencies**
   - Keep dependencies updated
   - Review security advisories
   - Use `uv pip` for consistent environment

3. **Testing**
   - Write tests for security checks
   - Test with malicious configurations
   - Verify no false negatives

## Known Limitations

### Not a Runtime Security Tool

This tool performs **static analysis** of Keycloak configurations. It does not:
- Monitor runtime behavior
- Detect active attacks
- Perform penetration testing
- Test actual OAuth flows

### Scope of Analysis

- Analyzes realm export files only
- Does not access live Keycloak instances
- Cannot detect configuration changes after export
- Limited to exported realm data (some settings not included)

### False Positives/Negatives

- Some configurations may be flagged incorrectly (false positives)
- Some issues may not be detected (false negatives)
- Context-dependent security decisions not captured

**Always combine with:**
- Manual security reviews
- Penetration testing
- Runtime monitoring
- Security awareness training

## Security Research

We welcome security research on this tool. If you find interesting attack vectors or edge cases, please share them:

1. Open a GitHub issue (for non-sensitive topics)
2. Submit a pull request with improved checks
3. Contact us privately for sensitive findings

## CVE References

This tool helps detect configurations vulnerable to known CVEs:

- **CVE-2023-6927** - Keycloak redirect URI bypass
- **CVE-2023-28131** - Expo PKCE bypass
- **CVE-2024-10318** - NGINX OIDC nonce validation

See [check-reference.md](check-reference.md) for complete CVE mappings.

## Acknowledgments

Security research and standards from:
- IETF OAuth Working Group
- OpenID Foundation
- OWASP Foundation
- Security researchers and contributors

---

**Thank you for helping keep the Keycloak and OAuth community secure!**
