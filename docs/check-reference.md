# Security Check Reference

Complete documentation of all security checks implemented in the Keycloak Configuration Security Analyzer.

**Total Checks**: 24

## Table of Contents

- [Critical Severity (5 checks)](#-severity-5-checks)
  - [KC-FLOW-001: Implicit Flow Enabled](#kc-flow-001-implicit-flow-enabled)
  - [KC-FLOW-003: Password Grant Enabled](#kc-flow-003-password-grant-enabled)
  - [KC-PKCE-001: PKCE Not Enforced](#kc-pkce-001-pkce-not-enforced)
  - [KC-PKCE-002: Weak PKCE Method (plain)](#kc-pkce-002-weak-pkce-method-(plain))
  - [KC-REDIR-001: Wildcard Redirect URI](#kc-redir-001-wildcard-redirect-uri)
- [High Severity (8 checks)](#-severity-8-checks)
  - [KC-REDIR-002: HTTP Redirect URI (Non-Localhost)](#kc-redir-002-http-redirect-uri-(non-localhost))
  - [KC-REDIR-003: Localhost in Production Redirect URIs](#kc-redir-003-localhost-in-production-redirect-uris)
  - [KC-REDIR-004: Path Traversal in Redirect URIs](#kc-redir-004-path-traversal-in-redirect-uris)
  - [KC-REDIR-005: Dangerous URI Schemes](#kc-redir-005-dangerous-uri-schemes)
  - [KC-TLS-001: SSL Not Required](#kc-tls-001-ssl-not-required)
  - [KC-TOKEN-001: Excessive Access Token Lifespan](#kc-token-001-excessive-access-token-lifespan)
  - [KC-TOKEN-002: Refresh Token Reuse Allowed](#kc-token-002-refresh-token-reuse-allowed)
  - [KC-TOKEN-005: Bearer Tokens Not Sender-Constrained](#kc-token-005-bearer-tokens-not-sender-constrained)
- [Medium Severity (6 checks)](#-severity-6-checks)
  - [KC-AUTH-001: Confidential Client Without Authentication](#kc-auth-001-confidential-client-without-authentication)
  - [KC-AUTH-002: Using Symmetric Client Authentication](#kc-auth-002-using-symmetric-client-authentication)
  - [KC-PKCE-003: PKCE Optional for Confidential Client](#kc-pkce-003-pkce-optional-for-confidential-client)
  - [KC-TLS-002: SSL External Only](#kc-tls-002-ssl-external-only)
  - [KC-TOKEN-003: Full Scope Allowed](#kc-token-003-full-scope-allowed)
  - [KC-TOKEN-004: Excessive Implicit Flow Token Lifespan](#kc-token-004-excessive-implicit-flow-token-lifespan)
- [Low Severity (3 checks)](#-severity-3-checks)
  - [KC-SEC-001: Brute Force Protection Disabled](#kc-sec-001-brute-force-protection-disabled)
  - [KC-MISC-005: Service Accounts Enabled (Review)](#kc-misc-005-service-accounts-enabled-review)
  - [KC-MISC-006: No User Consent Required](#kc-misc-006-no-user-consent-required)
- [Info Severity (2 checks)](#-severity-2-checks)
  - [KC-BP-001: Missing Client Description](#kc-bp-001-missing-client-description)
  - [KC-INFO-001: Client Secrets in Export](#kc-info-001-client-secrets-in-export)

---


## Critical Severity (5 checks)

### KC-FLOW-001: Implicit Flow Enabled

**Category**: OAuth Flows  
**Severity**: Critical

**Description**:
Check if implicit flow is enabled.

RFC 9700 Section 4.1.2: The implicit grant (response_type=token) SHOULD NOT be used.
Access tokens exposed in URLs leak through browser history, Referer headers, and
server logs.

**Standards & References**:
- RFC 9700 Section 4.1.2 - Implicit Grant Deprecated
- OAuth 2.1 - Implicit Grant Removed
- Proofpoint Research 2023 - OAuth Phishing Attacks

---

### KC-FLOW-003: Password Grant Enabled

**Category**: OAuth Flows  
**Severity**: Critical

**Description**:
Check if password grant (direct access grants) is enabled.

RFC 9700 Section 4.1.3: Resource owner password credentials grant MUST NOT be used.
This flow exposes user credentials directly to client applications.

**Standards & References**:
- RFC 9700 Section 4.1.3 - Password Grant Forbidden
- OAuth 2.1 - Resource Owner Password Removed
- OWASP OAuth Cheat Sheet

---

### KC-PKCE-001: PKCE Not Enforced

**Category**: PKCE  
**Severity**: Critical

**Description**:
Check if PKCE is enforced for public clients.

RFC 9700 Section 3.1: Authorization servers MUST enforce PKCE for
all public clients. PKCE with S256 challenge method prevents
authorization code interception attacks.

**Standards & References**:
- RFC 9700 Section 3.1 - PKCE Mandatory
- RFC 7636 - Proof Key for Code Exchange
- OAuth 2.1 Draft - PKCE Required
- CVE-2023-28131 - Expo PKCE bypass

---

### KC-PKCE-002: Weak PKCE Method (plain)

**Category**: PKCE  
**Severity**: Critical

**Description**:
Check if PKCE uses weak 'plain' method instead of S256.

RFC 9700 requires the S256 challenge method. The 'plain' method
exposes the code_verifier in the authorization request, breaking
the security model.

**Standards & References**:
- RFC 9700 Section 3.1
- RFC 7636 - S256 Required

---

### KC-REDIR-001: Wildcard Redirect URI

**Category**: Redirect URI Validation  
**Severity**: Critical

**Description**:
Check for wildcard redirect URIs.

RFC 9700 Section 4.1.1: Authorization servers MUST utilize exact string matching
for redirect URIs. Wildcards enable subdomain takeover and open redirect attacks.

**Standards & References**:
- RFC 9700 Section 4.1.1 - Exact Matching Required
- CVE-2023-6927 - Keycloak Redirect URI Bypass
- OAuth 2.0 Redirect URI Validation Falls Short (2023 Research)

---


## High Severity (8 checks)

### KC-REDIR-002: HTTP Redirect URI (Non-Localhost)

**Category**: Redirect URI Validation
**Severity**: High

**Description**:
Check for HTTP (non-HTTPS) redirect URIs.

RFC 8252: Authorization servers MUST NOT allow http:// redirect URIs
except for localhost (native apps).

**Standards & References**:
- RFC 8252 - OAuth 2.0 for Native Apps
- RFC 9700 Transport Security

---

### KC-REDIR-003: Localhost in Production Redirect URIs

**Category**: Redirect URI Validation
**Severity**: High

**Description**:
Check for localhost redirect URIs in production.

Development URIs (localhost, 127.0.0.1) in production configurations
expose systems to local attacks and session hijacking.

**Standards & References**:
- RFC 8252 - OAuth 2.0 for Native Apps
- OAuth 2.0 Security Best Practices

---

### KC-REDIR-004: Path Traversal in Redirect URIs

**Category**: Redirect URI Validation
**Severity**: High

**Description**:
Check for path traversal patterns in redirect URIs.

Parser differential attacks using ../, @, and URL encoding can bypass
naive validation and redirect authorization codes to attacker-controlled domains.

**Standards & References**:
- RFC 9700 Section 4.1.1 - Redirect URI Validation
- OAuth 2.0 Redirect URI Validation Research (2023)
- Parser Differential Attacks

---

### KC-REDIR-005: Dangerous URI Schemes

**Category**: Redirect URI Validation
**Severity**: High

**Description**:
Check for dangerous URI schemes in redirect URIs.

javascript:, data:, vbscript:, file:, and other dangerous schemes can execute
code or access local files, enabling XSS and other attacks.

**Standards & References**:
- RFC 9700 - Redirect URI Security
- OWASP XSS Prevention
- CVE-2023-28131 - Expo OAuth URI Scheme Vulnerability

---

### KC-TLS-001: SSL Not Required

**Category**: Transport Security  
**Severity**: High

**Description**:
Check if SSL/TLS is not required for the realm.

RFC 9700: TLS 1.2 or higher MUST be used for all OAuth endpoints.

**Standards & References**:
- RFC 9700 - Transport Security
- RFC 6749 Section 3.1 - TLS Required

---

### KC-TOKEN-001: Excessive Access Token Lifespan

**Category**: Token Security  
**Severity**: High

**Description**:
Check for excessive access token lifespans.

RFC 9700: Access tokens SHOULD have short lifespans to limit impact of theft.
Recommended: 5-15 minutes (300-900 seconds).

**Standards & References**:
- RFC 9700 Section 4.3 - Token Lifespans
- OAuth 2.0 Security Best Practices

---

### KC-TOKEN-002: Refresh Token Reuse Allowed

**Category**: Token Security
**Severity**: High

**Description**:
Check if refresh token reuse is allowed.

RFC 9700: Refresh token rotation SHOULD be implemented for public clients.

**Standards & References**:
- RFC 9700 Section 4.3.3 - Refresh Token Rotation
- OAuth 2.1 - Refresh Token Protection

---

### KC-TOKEN-005: Bearer Tokens Not Sender-Constrained

**Category**: Token Security
**Severity**: High

**Description**:
Check if bearer tokens are not sender-constrained.

RFC 9700: Bearer tokens SHOULD be sender-constrained using DPoP (RFC 9449)
or mTLS (RFC 8705) to prevent token theft and replay attacks.

**Standards & References**:
- RFC 9700 - Sender-Constrained Tokens
- RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)
- RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
- Cloudflare/Okta Breach (November 2023) - Unrotated bearer token

---


## Medium Severity (6 checks)

### KC-AUTH-001: Confidential Client Without Authentication

**Category**: Client Authentication  
**Severity**: Medium

**Description**:
Check if confidential clients lack authentication configuration.

RFC 6749: Confidential clients MUST authenticate with the authorization server.

**Standards & References**:
- RFC 6749 Section 2.3 - Client Authentication
- RFC 6749 Section 3.2.1 - Token Endpoint Authentication

---

### KC-AUTH-002: Using Symmetric Client Authentication

**Category**: Client Authentication  
**Severity**: Medium

**Description**:
Check if clients use symmetric authentication (client secrets).

FAPI 2.0 and best practices recommend asymmetric authentication methods
for better security.

**Standards & References**:
- FAPI 2.0 Security Profile - Asymmetric Authentication Required
- RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication
- OpenID Connect Core - private_key_jwt

---

### KC-PKCE-003: PKCE Optional for Confidential Client

**Category**: PKCE  
**Severity**: Medium

**Description**:
Recommend PKCE even for confidential clients.

While RFC 9700 mandates PKCE for public clients, it's also
recommended for confidential clients as defense-in-depth.

**Standards & References**:
- RFC 9700 Section 3.1 - Best Practice
- OAuth 2.1 - Defense in Depth

---

### KC-TLS-002: SSL External Only

**Category**: Transport Security  
**Severity**: Medium

**Description**:
Check if SSL is only required for external requests.

While 'external' is acceptable for development, production should use 'all'.

**Standards & References**:
- RFC 9700 - Transport Security Best Practices

---

### KC-TOKEN-003: Full Scope Allowed

**Category**: Token Security  
**Severity**: Medium

**Description**:
Check if clients have full scope allowed.

Best Practice: Limit scope to minimum required resources (principle of least privilege).

**Standards & References**:
- RFC 9700 Section 4.3.1 - Token Privilege Restriction
- Principle of Least Privilege

---

### KC-TOKEN-004: Excessive Implicit Flow Token Lifespan

**Category**: Token Security  
**Severity**: Medium

**Description**:
Check for excessive access token lifespan specifically for implicit flow.

While implicit flow should be disabled entirely, if it exists, token
lifespans should be very short.

**Standards & References**:
- RFC 9700 - Implicit Flow Deprecated
- OAuth 2.0 Security Best Practices

---


## Low Severity (3 checks)

### KC-SEC-001: Brute Force Protection Disabled

**Category**: Miscellaneous
**Severity**: Low

**Description**:
Check if brute force protection is disabled for the realm.

Brute force protection helps prevent password guessing attacks.

**Standards & References**:
- OWASP - Brute Force Attack Prevention
- Keycloak Security Best Practices

---

### KC-MISC-005: Service Accounts Enabled (Review)

**Category**: Miscellaneous
**Severity**: Low

**Description**:
Check if service accounts are enabled. Review necessity and audit usage.

While not inherently insecure, service accounts (client credentials grant) should
be reviewed to ensure they are necessary and properly audited.

**Standards & References**:
- OAuth 2.0 Client Credentials Grant
- Service Account Best Practices

---

### KC-MISC-006: No User Consent Required

**Category**: Miscellaneous
**Severity**: Low

**Description**:
Check if user consent is not required for third-party apps.

For third-party applications, users should explicitly approve access to their data
for transparency and compliance with privacy regulations.

**Standards & References**:
- OpenID Connect Core - Consent
- OAuth 2.0 User Consent Best Practices

---


## Info Severity (2 checks)

### KC-BP-001: Missing Client Description

**Category**: Miscellaneous  
**Severity**: Info

**Description**:
Check if clients are missing descriptions.

Descriptions help with documentation and maintenance.

**Standards & References**:
- Documentation Best Practices
- Keycloak Administration Guide

---

### KC-INFO-001: Client Secrets in Export

**Category**: Miscellaneous  
**Severity**: Info

**Description**:
Check if client secrets are present in the realm export.

Client secrets should not be stored in version control or shared via exports.

**Standards & References**:
- Security Best Practices - Secret Management
- OWASP - Sensitive Data Exposure

---


## How to Read This Reference

**Check ID**: Unique identifier for the security check (e.g., KC-PKCE-001)
- `KC` = Keycloak
- Second part indicates category (PKCE, FLOW, REDIR, TLS, TOKEN, AUTH, SEC, INFO, BP)
- Number is sequential within category

**Category**: Logical grouping of related checks

**Severity Levels**:
- **Critical**: Immediate exploitation risk, direct RFC violation, requires urgent remediation
- **High**: Serious security weakness, likely exploitable with moderate effort
- **Medium**: Security weakness requiring specific conditions, defense-in-depth violation
- **Low**: Minor security concern, best practice recommendation
- **Info**: Informational finding, operational hygiene, documentation

## Remediation

Each check includes detailed remediation guidance when findings are generated. To see complete remediation steps:
1. Run the analyzer: `keycloak-analyzer ./configs`
2. View findings in console, JSON, or HTML format
3. Each finding includes:
   - Detailed explanation of the security issue
   - Step-by-step remediation instructions
   - Keycloak Admin Console navigation
   - Code examples where applicable
   - Testing verification steps

## Adding Custom Checks

See `docs/adding-checks.md` for a guide on implementing custom security checks.

