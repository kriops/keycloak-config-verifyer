"""Redirect URI validation checks."""

from typing import List

from .base import SecurityCheck, security_check
from ..models import Finding, Severity, FindingCategory, ClientConfig, RealmConfig


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

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> List[Finding]:
        findings = []

        if client.has_wildcard_redirect:
            # Collect all wildcard URIs
            wildcard_uris = [
                uri
                for uri in client.redirectUris
                if '*' in uri or uri == '' or '+' in uri
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
                        f"**Attack Vectors:**\n\n"
                        f"1. **Subdomain Takeover:**\n"
                        f"   - Pattern: https://*.example.com/*\n"
                        f"   - Attacker registers expired subdomain (e.g., old.example.com)\n"
                        f"   - Attacker points subdomain to their infrastructure\n"
                        f"   - Attacker receives authorization codes at https://old.example.com/callback\n\n"
                        f"2. **Path Traversal:**\n"
                        f"   - Pattern: https://example.com/*\n"
                        f"   - Attacker uses: https://example.com/../../attacker.com\n"
                        f"   - Browser path normalization may redirect to attacker domain\n\n"
                        f"3. **Open Redirect Exploitation:**\n"
                        f"   - Attacker finds open redirector on allowed domain\n"
                        f"   - Crafts: https://example.com/redirect?url=https://attacker.com\n"
                        f"   - Authorization code forwarded to attacker\n\n"
                        f"4. **Fragment Reattachment:**\n"
                        f"   - Browsers automatically reattach URL fragments\n"
                        f"   - Enables token theft in certain flow configurations\n\n"
                        f"**Real-World Exploits:**\n"
                        f"- CVE-2023-6927: Keycloak wildcard patterns with prefix matching bypass\n"
                        f"- 2023 Research: GitHub and NAVER redirect URI vulnerabilities\n"
                        f"- Attackers stole authorization codes from major identity providers\n\n"
                        f"**RFC 9700 Requirement:** Authorization servers MUST use exact string "
                        f"matching (RFC 3986 Section 6.2.1). No wildcards, no pattern matching."
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
                origin for origin in client.webOrigins if '*' in origin or origin == '+'
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
                        f"**Security Impact:**\n"
                        f"- Wildcard '*' allows ALL origins (complete CORS bypass)\n"
                        f"- Wildcard '+' allows all Keycloak clients (overly permissive)\n"
                        f"- Enables cross-site scripting attacks\n"
                        f"- Allows malicious sites to make authenticated requests\n\n"
                        f"**Attack Scenario:**\n"
                        f"1. User visits attacker's website (attacker.com)\n"
                        f"2. Attacker's JavaScript makes API requests to your service\n"
                        f"3. Browser includes user's authentication cookies/tokens\n"
                        f"4. Attacker gains access to user's data"
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

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> List[Finding]:
        findings = []

        if client.has_http_redirect:
            # Collect non-localhost HTTP URIs
            http_uris = [
                uri
                for uri in client.redirectUris
                if uri.startswith('http://')
                and 'localhost' not in uri
                and '127.0.0.1' not in uri
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
                            f"**Attack Vectors:**\n\n"
                            f"1. **Network Eavesdropping:**\n"
                            f"   - Authorization codes transmitted in cleartext\n"
                            f"   - Attackers on network (WiFi, ISP, etc.) can intercept codes\n"
                            f"   - Man-in-the-middle (MitM) attacks\n\n"
                            f"2. **Code Interception:**\n"
                            f"   - Attacker intercepts: http://app.example.com/callback?code=AUTH_CODE\n"
                            f"   - Attacker exchanges code for access token\n"
                            f"   - Account takeover\n\n"
                            f"3. **DNS Hijacking:**\n"
                            f"   - HTTP connections don't verify server identity\n"
                            f"   - Attacker redirects DNS to malicious server\n"
                            f"   - Captures authorization codes\n\n"
                            f"**RFC 8252 Requirement:** Authorization servers MUST NOT allow "
                            f"http:// redirect URIs except localhost for native apps.\n\n"
                            f"**Note:** http://localhost and http://127.0.0.1 are permitted "
                            f"for native app development."
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
