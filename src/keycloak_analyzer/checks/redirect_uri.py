"""Redirect URI validation checks."""

from urllib.parse import urlparse

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class WildcardRedirectURICheck(SecurityCheck):
    """
    Check for wildcard redirect URIs.

    RFC 9700 Section 4.1.1: Authorization servers MUST utilize exact string matching
    for redirect URIs. Wildcards enable subdomain takeover and open redirect attacks.
    """

    check_id = "KC-REDIR-001"
    check_name = "Wildcard Redirect URI"
    category = FindingCategory.REDIRECT_URI
    default_severity = Severity.CRITICAL
    references = [
        "RFC 9700 Section 4.1.1 - Exact Matching Required",
        "CVE-2023-6927 - Keycloak Redirect URI Bypass",
        "OAuth 2.0 Redirect URI Validation Falls Short (2023 Research)",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        if client.has_wildcard_redirect:
            # Collect all wildcard URIs
            wildcard_uris = [
                uri for uri in client.redirectUris if "*" in uri or uri == "" or "+" in uri
            ]

            findings.append(
                self.create_finding(
                    title=f"Wildcard redirect URIs in client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' uses **wildcard patterns** in redirect URIs, "
                        f"which is a **critical security vulnerability**.\n\n"
                        f"**Detected Wildcard URIs:**\n"
                        + "\n".join(f"  - {uri}" for uri in wildcard_uris)
                        + "\n\n"
                        "**Attack Vectors:**\n\n"
                        "1. **Subdomain Takeover:**\n"
                        "   - Pattern: https://*.example.com/*\n"
                        "   - Attacker registers expired subdomain (e.g., old.example.com)\n"
                        "   - Attacker points subdomain to their infrastructure\n"
                        "   - Attacker receives authorization codes at https://old.example.com/callback\n\n"
                        "2. **Path Traversal:**\n"
                        "   - Pattern: https://example.com/*\n"
                        "   - Attacker uses: https://example.com/../../attacker.com\n"
                        "   - Browser path normalization may redirect to attacker domain\n\n"
                        "3. **Open Redirect Exploitation:**\n"
                        "   - Attacker finds open redirector on allowed domain\n"
                        "   - Crafts: https://example.com/redirect?url=https://attacker.com\n"
                        "   - Authorization code forwarded to attacker\n\n"
                        "4. **Fragment Reattachment:**\n"
                        "   - Browsers automatically reattach URL fragments\n"
                        "   - Enables token theft in certain flow configurations\n\n"
                        "**Real-World Exploits:**\n"
                        "- CVE-2023-6927: Keycloak wildcard patterns with prefix matching bypass\n"
                        "- 2023 Research: GitHub and NAVER redirect URI vulnerabilities\n"
                        "- Attackers stole authorization codes from major identity providers\n\n"
                        "**RFC 9700 Requirement:** Authorization servers MUST use exact string "
                        "matching (RFC 3986 Section 6.2.1). No wildcards, no pattern matching."
                    ),
                    remediation=(
                        f"Replace wildcard redirect URIs with explicit, exact URIs:\n\n"
                        f"**Step 1: Identify Required Redirect URIs**\n"
                        f"List all legitimate callback URLs your application uses:\n"
                        f"  - Production: https://app.example.com/auth/callback\n"
                        f"  - Staging: https://staging.example.com/auth/callback\n"
                        f"  - Local Dev: http://localhost:3000/callback (localhost OK)\n\n"
                        f"**Step 2: Update Keycloak Configuration**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. In 'Valid Redirect URIs' field:\n"
                        f"   - **Remove ALL wildcard patterns** (*, +, etc.)\n"
                        f"   - **Add each exact URI** on separate lines\n"
                        f"   - Example:\n"
                        f"     https://app.example.com/auth/callback\n"
                        f"     https://staging.example.com/auth/callback\n"
                        f"     http://localhost:3000/callback\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 3: Update Application Configuration**\n"
                        f"Ensure your app uses exact redirect URIs:\n"
                        f"```javascript\n"
                        f"const redirectUri = 'https://app.example.com/auth/callback';\n"
                        f"// NOT: const redirectUri = 'https://*.example.com/*';\n"
                        f"```\n\n"
                        f"**Step 4: Verification**\n"
                        f"1. Test authentication flow with each configured URI\n"
                        f"2. Verify authorization fails with modified URIs\n"
                        f"3. Test that slight variations (extra path, subdomain) are rejected\n\n"
                        f"**Important:** Each environment needs its own explicit redirect URI. "
                        f"Never use wildcards as a shortcut."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "wildcard_uris": wildcard_uris,
                        "total_redirect_uris": len(client.redirectUris),
                    },
                )
            )

        # Also check web origins
        if client.has_wildcard_web_origin:
            wildcard_origins = [
                origin for origin in client.webOrigins if "*" in origin or origin == "+"
            ]

            findings.append(
                self.create_finding(
                    title=f"Wildcard web origins in client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' uses **wildcard patterns** in web origins (CORS), "
                        f"which allows any domain to make requests to your API.\n\n"
                        f"**Detected Wildcard Origins:**\n"
                        + "\n".join(f"  - {origin}" for origin in wildcard_origins)
                        + "\n\n"
                        "**Security Impact:**\n"
                        "- Wildcard '*' allows ALL origins (complete CORS bypass)\n"
                        "- Wildcard '+' allows all Keycloak clients (overly permissive)\n"
                        "- Enables cross-site scripting attacks\n"
                        "- Allows malicious sites to make authenticated requests\n\n"
                        "**Attack Scenario:**\n"
                        "1. User visits attacker's website (attacker.com)\n"
                        "2. Attacker's JavaScript makes API requests to your service\n"
                        "3. Browser includes user's authentication cookies/tokens\n"
                        "4. Attacker gains access to user's data"
                    ),
                    remediation=(
                        f"Replace wildcard web origins with explicit domains:\n\n"
                        f"**Keycloak Configuration:**\n"
                        f"1. Navigate to: Clients → '{client.clientId}'\n"
                        f"2. Go to: Settings tab\n"
                        f"3. In 'Web Origins' field:\n"
                        f"   - Remove '*' and '+'\n"
                        f"   - Add exact origins:\n"
                        f"     https://app.example.com\n"
                        f"     https://staging.example.com\n"
                        f"4. Click 'Save'\n\n"
                        f"**Note:** Only add origins that need to make CORS requests to your API."
                    ),
                    realm=realm,
                    client=client,
                    severity=Severity.MEDIUM,
                    evidence={
                        "client_id": client.clientId,
                        "wildcard_origins": wildcard_origins,
                    },
                )
            )

        return findings


@security_check
class HTTPRedirectURICheck(SecurityCheck):
    """
    Check for HTTP (non-HTTPS) redirect URIs.

    RFC 8252: Authorization servers MUST NOT allow http:// redirect URIs
    except for localhost (native apps).
    """

    check_id = "KC-REDIR-002"
    check_name = "HTTP Redirect URI (Non-Localhost)"
    category = FindingCategory.REDIRECT_URI
    default_severity = Severity.HIGH
    references = [
        "RFC 8252 - OAuth 2.0 for Native Apps",
        "RFC 9700 Transport Security",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        if client.has_http_redirect:
            # Collect non-localhost HTTP URIs
            http_uris = [
                uri
                for uri in client.redirectUris
                if uri.startswith("http://") and "localhost" not in uri and "127.0.0.1" not in uri
            ]

            if http_uris:
                findings.append(
                    self.create_finding(
                        title=f"HTTP redirect URIs (non-localhost) in client '{client.clientId}'",
                        description=(
                            f"Client '{client.clientId}' uses **unencrypted HTTP redirect URIs**, "
                            f"exposing authorization codes to network attacks.\n\n"
                            f"**Vulnerable URIs:**\n"
                            + "\n".join(f"  - {uri}" for uri in http_uris)
                            + "\n\n"
                            "**Attack Vectors:**\n\n"
                            "1. **Network Eavesdropping:**\n"
                            "   - Authorization codes transmitted in cleartext\n"
                            "   - Attackers on network (WiFi, ISP, etc.) can intercept codes\n"
                            "   - Man-in-the-middle (MitM) attacks\n\n"
                            "2. **Code Interception:**\n"
                            "   - Attacker intercepts: http://app.example.com/callback?code=AUTH_CODE\n"
                            "   - Attacker exchanges code for access token\n"
                            "   - Account takeover\n\n"
                            "3. **DNS Hijacking:**\n"
                            "   - HTTP connections don't verify server identity\n"
                            "   - Attacker redirects DNS to malicious server\n"
                            "   - Captures authorization codes\n\n"
                            "**RFC 8252 Requirement:** Authorization servers MUST NOT allow "
                            "http:// redirect URIs except localhost for native apps.\n\n"
                            "**Note:** http://localhost and http://127.0.0.1 are permitted "
                            "for native app development."
                        ),
                        remediation=(
                            f"Migrate HTTP redirect URIs to HTTPS:\n\n"
                            f"**Step 1: Obtain TLS Certificate**\n"
                            f"For each domain, obtain a valid TLS certificate:\n"
                            f"  - Use Let's Encrypt (free, automated)\n"
                            f"  - Or commercial CA (DigiCert, Sectigo, etc.)\n\n"
                            f"**Step 2: Configure HTTPS on Web Server**\n"
                            f"Enable TLS 1.2+ on your web server:\n"
                            f"  - Apache: Enable mod_ssl, configure VirtualHost\n"
                            f"  - Nginx: Configure ssl_certificate and ssl_certificate_key\n"
                            f"  - Cloud: Enable HTTPS in load balancer/CDN settings\n\n"
                            f"**Step 3: Update Redirect URIs**\n"
                            f"1. Log into Keycloak Admin Console\n"
                            f"2. Navigate to: Clients → '{client.clientId}'\n"
                            f"3. Go to: Settings tab\n"
                            f"4. In 'Valid Redirect URIs':\n"
                            f"   - Replace http:// with https://\n"
                            f"   - Example:\n"
                            f"     http://app.example.com/callback → https://app.example.com/callback\n"
                            f"5. Click 'Save'\n\n"
                            f"**Step 4: Update Application**\n"
                            f"```javascript\n"
                            f"const redirectUri = 'https://app.example.com/callback';\n"
                            f"// NOT: const redirectUri = 'http://app.example.com/callback';\n"
                            f"```\n\n"
                            f"**Step 5: Enforce HTTPS Redirect**\n"
                            f"Configure web server to redirect HTTP to HTTPS:\n"
                            f"```nginx\n"
                            f"server {{\n"
                            f"    listen 80;\n"
                            f"    return 301 https://$host$request_uri;\n"
                            f"}}\n"
                            f"```\n\n"
                            f"**For Development:** Use http://localhost:3000 for local testing only."
                        ),
                        realm=realm,
                        client=client,
                        evidence={
                            "client_id": client.clientId,
                            "http_uris": http_uris,
                        },
                    )
                )

        return findings


@security_check
class LocalhostInProductionCheck(SecurityCheck):
    """
    Check for localhost redirect URIs in production.

    Development URIs (localhost, 127.0.0.1) in production configurations
    expose systems to local attacks and session hijacking.
    """

    check_id = "KC-REDIR-003"
    check_name = "Localhost in Production Redirect URIs"
    category = FindingCategory.REDIRECT_URI
    default_severity = Severity.HIGH
    references = [
        "RFC 8252 - OAuth 2.0 for Native Apps",
        "OAuth 2.0 Security Best Practices",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Check for localhost/127.0.0.1 in redirect URIs
        localhost_uris = [
            uri
            for uri in client.redirectUris
            if "localhost" in uri.lower() or "127.0.0.1" in uri or "[::1]" in uri
        ]

        if localhost_uris:
            findings.append(
                self.create_finding(
                    title=f"Localhost redirect URIs in client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has **localhost redirect URIs**, which are "
                        f"intended for development only and should not be in production.\n\n"
                        f"**Detected Localhost URIs:**\n"
                        + "\n".join(f"  - {uri}" for uri in localhost_uris)
                        + "\n\n"
                        "**Security Risks:**\n\n"
                        "1. **Local Session Hijacking:**\n"
                        "   - Malware on user's machine can intercept localhost callbacks\n"
                        "   - Authorization codes delivered to http://localhost:* are accessible to any local process\n"
                        "   - No same-origin policy protection for localhost\n\n"
                        "2. **Production Configuration Leak:**\n"
                        "   - Development URIs in production indicate configuration management issues\n"
                        "   - May expose test/debug endpoints\n"
                        "   - Increases attack surface\n\n"
                        "3. **User Confusion:**\n"
                        "   - Production users see localhost URIs (broken auth flow)\n"
                        "   - Poor user experience\n\n"
                        "**Attack Scenario:**\n"
                        "1. User authenticates via OAuth flow\n"
                        "2. Attacker's malware listens on localhost port\n"
                        "3. Authorization code delivered to malicious localhost listener\n"
                        "4. Attacker exchanges code for access token\n\n"
                        "**Note:** Localhost URIs are acceptable for native apps during development "
                        "but MUST NOT be present in production Keycloak configurations."
                    ),
                    remediation=(
                        f"Remove localhost redirect URIs from production configuration:\n\n"
                        f"**Step 1: Identify Legitimate Production URIs**\n"
                        f"Replace localhost URIs with actual production domains:\n"
                        f"  - Production: https://app.example.com/callback\n"
                        f"  - Staging: https://staging.example.com/callback\n\n"
                        f"**Step 2: Update Keycloak Configuration**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. In 'Valid Redirect URIs':\n"
                        f"   - **Remove all localhost URIs:**\n"
                        + "\n".join(f"     ❌ {uri}" for uri in localhost_uris)
                        + "\n"
                        "   - **Add production URIs:**\n"
                        "     ✓ https://app.example.com/callback\n"
                        "5. Click 'Save'\n\n"
                        "**Step 3: Separate Development Configuration**\n"
                        "Create separate Keycloak clients for development:\n"
                        "  - Client: 'my-app-prod' → Production URIs only\n"
                        "  - Client: 'my-app-dev' → Localhost URIs for dev\n\n"
                        "**Step 4: Configuration Management**\n"
                        "Use environment-specific configuration:\n"
                        "```javascript\n"
                        "const redirectUri = process.env.NODE_ENV === 'production'\n"
                        "  ? 'https://app.example.com/callback'\n"
                        "  : 'http://localhost:3000/callback';\n"
                        "```\n\n"
                        "**Best Practice:** Never use the same Keycloak client for both "
                        "development and production."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "localhost_uris": localhost_uris,
                    },
                )
            )

        return findings


@security_check
class PathTraversalRedirectURICheck(SecurityCheck):
    """
    Check for path traversal patterns in redirect URIs.

    Parser differential attacks using ../,  @, and URL encoding can bypass
    naive validation and redirect authorization codes to attacker-controlled domains.
    """

    check_id = "KC-REDIR-004"
    check_name = "Path Traversal in Redirect URIs"
    category = FindingCategory.REDIRECT_URI
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 Section 4.1.1 - Redirect URI Validation",
        "OAuth 2.0 Redirect URI Validation Research (2023)",
        "Parser Differential Attacks",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Patterns that indicate potential path traversal or parser confusion
        # These patterns should only be checked in the path component, not the scheme
        path_patterns = [
            ("../", "Parent directory traversal"),
            ("./", "Relative path"),
            (".//", "Double slash relative path"),
            ("//", "Double slash in path"),
            ("@", "Username in URL (parser confusion)"),
            ("%2e%2e", "URL-encoded dot-dot"),
            ("%2f", "URL-encoded slash"),
            ("%5c", "URL-encoded backslash"),
            ("\\", "Backslash (Windows path separator)"),
            ("%00", "Null byte injection"),
        ]

        suspicious_uris = []
        for uri in client.redirectUris:
            uri_lower = uri.lower()

            # Check for protocol-relative URLs (start with //)
            if uri_lower.startswith("//"):
                suspicious_uris.append((uri, "//", "Protocol-relative URL"))
                continue

            # Parse URL to extract components
            try:
                parsed = urlparse(uri_lower)

                # Check for @ symbol in netloc (parser confusion attack)
                # Example: https://good.com@attacker.com/callback
                if "@" in parsed.netloc:
                    suspicious_uris.append((uri, "@", "Username in URL (parser confusion)"))
                    continue

                # Check for backslash in netloc (Windows path separator confusion)
                # Example: https://example.com\attacker.com
                if "\\" in parsed.netloc:
                    suspicious_uris.append((uri, "\\", "Backslash (Windows path separator)"))
                    continue

                # Only check patterns in the path component (after the domain)
                path = parsed.path
                query = parsed.query
                fragment = parsed.fragment

                # Combine path, query, and fragment for pattern checking
                # (patterns could appear in query params or fragments too)
                path_and_params = (
                    path + ("?" + query if query else "") + ("#" + fragment if fragment else "")
                )

                for pattern, description in path_patterns:
                    if pattern in path_and_params:
                        suspicious_uris.append((uri, pattern, description))
                        break  # Only report once per URI
            except Exception:
                # If parsing fails, fall back to simple check but skip '//'
                # (malformed URIs are suspicious anyway)
                for pattern, description in path_patterns:
                    if pattern == "//" and not uri_lower.startswith("//"):
                        # Skip checking '//' in the middle if we already checked the start
                        continue
                    if pattern in uri_lower:
                        suspicious_uris.append((uri, pattern, description))
                        break  # Only report once per URI

        if suspicious_uris:
            findings.append(
                self.create_finding(
                    title=f"Path traversal patterns in redirect URIs for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has redirect URIs with **dangerous path traversal patterns** "
                        f"that may bypass validation and enable authorization code theft.\n\n"
                        f"**Detected Suspicious URIs:**\n"
                        + "\n".join(
                            f"  - `{uri}` → {pattern} ({desc})"
                            for uri, pattern, desc in suspicious_uris
                        )
                        + "\n\n"
                        "**Attack Vectors:**\n\n"
                        "1. **Parser Differential Attacks:**\n"
                        "   - Different parsers interpret URLs differently\n"
                        "   - Example: `https://good.com/../attacker.com`\n"
                        "   - Validator sees good.com, browser goes to attacker.com\n\n"
                        "2. **URL Encoding Bypasses:**\n"
                        "   - `%2e%2e` decodes to `..`\n"
                        "   - Validation checks literal string, browser normalizes\n"
                        "   - Bypass: `https://good.com/%2e%2e/attacker.com`\n\n"
                        "3. **@ Symbol Confusion:**\n"
                        "   - `https://good.com@attacker.com` → attacker.com\n"
                        "   - Parser sees 'good.com' as username, ignores it\n"
                        "   - Browser connects to attacker.com\n\n"
                        "4. **Protocol-Relative URLs:**\n"
                        "   - `//attacker.com/callback`\n"
                        "   - Inherits protocol from current page\n"
                        "   - May bypass origin checks\n\n"
                        "**Real-World Impact:**\n"
                        "- 2023 Security Research: GitHub and NAVER vulnerable to parser differentials\n"
                        "- Authorization code theft via redirect URI manipulation\n"
                        "- Account takeover attacks"
                    ),
                    remediation=(
                        f"Remove redirect URIs with path traversal patterns:\n\n"
                        f"**Step 1: Review and Replace Suspicious URIs**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. In 'Valid Redirect URIs', remove:\n"
                        + "\n".join(f"   ❌ {uri}" for uri, _, _ in suspicious_uris)
                        + "\n\n"
                        "**Step 2: Use Only Clean, Absolute URIs**\n"
                        "✓ **GOOD:** Absolute URIs with explicit protocol:\n"
                        "  - https://app.example.com/callback\n"
                        "  - https://staging.example.com/auth/callback\n\n"
                        "❌ **BAD:** URIs with special characters or encoding:\n"
                        "  - https://app.example.com/../callback\n"
                        "  - https://good.com@attacker.com\n"
                        "  - //example.com/callback\n"
                        "  - https://app.example.com/%2e%2e/callback\n\n"
                        "**Step 3: Validation Rules**\n"
                        "Ensure redirect URIs:\n"
                        "  - Start with https:// (or http://localhost for dev)\n"
                        "  - Contain no /../, ./, //, @, or URL encoding\n"
                        "  - Use only alphanumeric, hyphen, dot, slash, colon\n"
                        "  - Are fully normalized (no path simplification needed)\n\n"
                        "**Step 4: Test Validation**\n"
                        "Verify these malicious URIs are REJECTED:\n"
                        "  - https://app.example.com/../attacker.com\n"
                        "  - https://good.com@attacker.com\n"
                        "  - //attacker.com/callback\n"
                        "  - https://app.example.com/%252e%252e/callback\n\n"
                        "**RFC 9700 Requirement:** Use exact string matching with no "
                        "normalization or encoding."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "suspicious_uris": [
                            {"uri": uri, "pattern": pattern, "reason": desc}
                            for uri, pattern, desc in suspicious_uris
                        ],
                    },
                )
            )

        return findings


@security_check
class DangerousURISchemeCheck(SecurityCheck):
    """
    Check for dangerous URI schemes in redirect URIs.

    javascript:, data:, vbscript:, file:, and other dangerous schemes can execute
    code or access local files, enabling XSS and other attacks.
    """

    check_id = "KC-REDIR-005"
    check_name = "Dangerous URI Schemes"
    category = FindingCategory.REDIRECT_URI
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 - Redirect URI Security",
        "OWASP XSS Prevention",
        "CVE-2023-28131 - Expo OAuth URI Scheme Vulnerability",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Dangerous URI schemes that can execute code or access local resources
        dangerous_schemes = [
            ("javascript:", "JavaScript execution (XSS)"),
            ("data:", "Data URI execution (XSS)"),
            ("vbscript:", "VBScript execution (IE)"),
            ("file:", "Local file system access"),
            ("about:", "Browser internal pages"),
            ("blob:", "Binary data execution"),
            ("filesystem:", "Local file system"),
        ]

        dangerous_uris = []
        for uri in client.redirectUris:
            uri_lower = uri.lower()
            for scheme, description in dangerous_schemes:
                if uri_lower.startswith(scheme):
                    dangerous_uris.append((uri, scheme, description))
                    break

        if dangerous_uris:
            findings.append(
                self.create_finding(
                    title=f"Dangerous URI schemes in redirect URIs for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has redirect URIs using **dangerous URI schemes** "
                        f"that can execute arbitrary code or access local files.\n\n"
                        f"**Detected Dangerous URIs:**\n"
                        + "\n".join(
                            f"  - `{uri}` → {scheme} ({desc})"
                            for uri, scheme, desc in dangerous_uris
                        )
                        + "\n\n"
                        "**Attack Vectors:**\n\n"
                        "1. **javascript: Scheme (XSS):**\n"
                        "   - Redirect: `javascript:alert(document.cookie)`\n"
                        "   - Browser executes JavaScript in page context\n"
                        "   - Attacker steals tokens, cookies, session data\n"
                        "   - **Impact:** Full account takeover via XSS\n\n"
                        "2. **data: Scheme (XSS):**\n"
                        "   - Redirect: `data:text/html,<script>alert(1)</script>`\n"
                        "   - Browser renders HTML with JavaScript\n"
                        "   - Bypasses Content Security Policy in some browsers\n"
                        "   - Can inject malicious content\n\n"
                        "3. **file: Scheme (Local File Access):**\n"
                        "   - Redirect: `file:///etc/passwd`\n"
                        "   - Accesses local file system\n"
                        "   - Information disclosure\n"
                        "   - May bypass same-origin policy\n\n"
                        "4. **vbscript: Scheme (Code Execution - IE):**\n"
                        "   - Legacy Internet Explorer\n"
                        "   - Executes VBScript code\n"
                        "   - Full system compromise possible\n\n"
                        "**Real-World Exploits:**\n"
                        "- CVE-2023-28131 (CVSS 9.6 Critical): Expo framework allowed custom "
                        "URI schemes, leading to credential leakage\n"
                        "- XSS attacks via OAuth redirect URI manipulation\n"
                        "- Token theft through javascript: scheme injection\n\n"
                        "**RFC 9700:** Only https:// (and http://localhost for native apps) "
                        "should be allowed in redirect URIs."
                    ),
                    remediation=(
                        f"Remove all dangerous URI schemes from redirect URIs:\n\n"
                        f"**Step 1: Immediate Action - Remove Dangerous URIs**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. In 'Valid Redirect URIs', **IMMEDIATELY REMOVE:**\n"
                        + "\n".join(f"   🚨 {uri}" for uri, _, _ in dangerous_uris)
                        + "\n"
                        "5. Click 'Save'\n\n"
                        "**Step 2: Use Only Safe URI Schemes**\n"
                        "✓ **ALLOWED Schemes:**\n"
                        "  - https:// - Secure HTTP (production)\n"
                        "  - http://localhost - Local development only\n"
                        "  - http://127.0.0.1 - Local development only\n"
                        "  - Custom schemes for native apps (with extreme caution)\n\n"
                        "❌ **FORBIDDEN Schemes:**\n"
                        "  - javascript: - Code execution\n"
                        "  - data: - Data URI execution\n"
                        "  - vbscript: - VBScript execution\n"
                        "  - file: - Local file access\n"
                        "  - about: - Browser internals\n"
                        "  - blob: - Binary data\n\n"
                        "**Step 3: Replace with Secure Redirect URIs**\n"
                        "Use standard HTTPS URLs:\n"
                        "```\n"
                        "https://app.example.com/callback\n"
                        "https://staging.example.com/auth/callback\n"
                        "http://localhost:3000/callback  # Dev only\n"
                        "```\n\n"
                        "**Step 4: Audit and Test**\n"
                        "1. Review all redirect URIs for your application\n"
                        "2. Verify only https:// and http://localhost remain\n"
                        "3. Test authentication flow end-to-end\n"
                        "4. Confirm no XSS or code execution possible\n\n"
                        "**Critical:** This is a **severe security vulnerability**. "
                        "Fix immediately to prevent code execution attacks."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "dangerous_uris": [
                            {"uri": uri, "scheme": scheme, "risk": desc}
                            for uri, scheme, desc in dangerous_uris
                        ],
                    },
                )
            )

        return findings
