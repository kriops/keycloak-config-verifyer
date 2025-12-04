"""Transport security checks."""

from ..models import Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class SSLNotRequiredCheck(SecurityCheck):
    """
    Check if SSL/TLS is not required for the realm.

    RFC 9700: TLS 1.2 or higher MUST be used for all OAuth endpoints.
    """

    check_id = "KC-TLS-001"
    check_name = "SSL Not Required"
    category = FindingCategory.TRANSPORT
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 - Transport Security",
        "RFC 6749 Section 3.1 - TLS Required",
    ]

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        if realm.ssl_disabled:
            findings.append(
                self.create_finding(
                    title=f"SSL completely disabled for realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' has SSL/TLS **completely disabled** "
                        f"(sslRequired: 'none'), allowing **unencrypted OAuth communications**.\n\n"
                        f"**Critical Security Impact:**\n"
                        f"1. **Credentials in Cleartext:** Usernames and passwords transmitted without encryption\n"
                        f"2. **Token Exposure:** Access tokens, refresh tokens, and ID tokens sent unencrypted\n"
                        f"3. **Authorization Code Interception:** Codes can be intercepted on the network\n"
                        f"4. **Session Hijacking:** Session cookies vulnerable to theft\n"
                        f"5. **Man-in-the-Middle Attacks:** Attackers can intercept and modify all traffic\n\n"
                        f"**Attack Scenario:**\n"
                        f"- User connects to OAuth endpoints over HTTP\n"
                        f"- Attacker on network (WiFi, ISP, corporate proxy) intercepts traffic\n"
                        f"- Attacker captures username, password, and tokens\n"
                        f"- Attacker impersonates user with stolen credentials\n\n"
                        f"**RFC 6749 Requirement:** TLS is REQUIRED for authorization endpoints, "
                        f"token endpoints, and when transmitting credentials.\n\n"
                        f"**RFC 9700:** TLS 1.2 or higher MUST be used."
                    ),
                    remediation=(
                        f"Enable SSL/TLS for realm '{realm.realm}':\n\n"
                        f"**Step 1: Keycloak Configuration**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: General tab\n"
                        f"4. Set 'Require SSL' to: **'all requests'** (most secure)\n"
                        f"   - 'all requests': HTTPS required for all connections\n"
                        f"   - 'external requests': HTTPS for internet, HTTP for localhost\n"
                        f"   - 'none': NO ENCRYPTION (current - DO NOT USE)\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 2: Configure TLS on Keycloak Server**\n"
                        f"Ensure Keycloak server has valid TLS certificate:\n"
                        f"```bash\n"
                        f"# Generate certificate (example - use proper CA in production)\n"
                        f"keytool -genkeypair -keyalg RSA -keysize 2048 \\\n"
                        f"  -validity 365 -alias server -keystore keystore.jks\n\n"
                        f"# Configure Keycloak to use certificate\n"
                        f"# In standalone.xml or via CLI\n"
                        f"```\n\n"
                        f"**Step 3: Enforce HTTPS in Reverse Proxy (if applicable)**\n"
                        f"If using nginx/Apache as reverse proxy:\n"
                        f"```nginx\n"
                        f"server {{\n"
                        f"    listen 443 ssl http2;\n"
                        f"    ssl_certificate /path/to/cert.pem;\n"
                        f"    ssl_certificate_key /path/to/key.pem;\n"
                        f"    ssl_protocols TLSv1.2 TLSv1.3;\n"
                        f"}}\n"
                        f"```\n\n"
                        f"**Step 4: Update Client Redirect URIs**\n"
                        f"Ensure all redirect URIs use https:// (not http://)\n\n"
                        f"**Step 5: Test**\n"
                        f"- Verify HTTPS works: https://your-keycloak-domain\n"
                        f"- Confirm HTTP is blocked or redirects to HTTPS\n"
                        f"- Test OAuth flow over HTTPS"
                    ),
                    realm=realm,
                    severity=Severity.CRITICAL,
                    evidence={
                        "realm": realm.realm,
                        "ssl_required": realm.sslRequired,
                    },
                )
            )

        return findings


@security_check
class SSLExternalOnlyCheck(SecurityCheck):
    """
    Check if SSL is only required for external requests.

    While 'external' is acceptable for development, production should use 'all'.
    """

    check_id = "KC-TLS-002"
    check_name = "SSL External Only"
    category = FindingCategory.TRANSPORT
    default_severity = Severity.MEDIUM
    references = [
        "RFC 9700 - Transport Security Best Practices",
    ]

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        if realm.sslRequired == "external":
            findings.append(
                self.create_finding(
                    title=f"SSL only required for external requests in realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' has SSL set to **'external requests only'**, "
                        f"which allows unencrypted internal traffic.\n\n"
                        f"**Configuration:** sslRequired = 'external'\n"
                        f"- HTTPS required for internet-facing connections\n"
                        f"- HTTP allowed for localhost/internal connections\n\n"
                        f"**Potential Issues:**\n"
                        f"1. **Internal Network Attacks:** If internal network is compromised, "
                        f"traffic can be intercepted\n"
                        f"2. **Misconfiguration Risk:** May accidentally allow HTTP in production "
                        f"if load balancer/proxy headers not set correctly\n"
                        f"3. **Compliance:** Some standards (PCI DSS, HIPAA) require encryption "
                        f"for ALL traffic, including internal\n\n"
                        f"**When 'external' is acceptable:**\n"
                        f"- Development/testing environments\n"
                        f"- Trusted internal networks with other security controls\n"
                        f"- Performance-critical internal services (with proper network segmentation)\n\n"
                        f"**Best Practice:** Production realms should use 'all requests' to "
                        f"enforce HTTPS everywhere."
                    ),
                    remediation=(
                        f"Consider upgrading SSL requirement for realm '{realm.realm}':\n\n"
                        f"**For Production Environments:**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: General tab\n"
                        f"4. Change 'Require SSL' from 'external requests' to **'all requests'**\n"
                        f"5. Click 'Save'\n\n"
                        f"**For Development Environments:**\n"
                        f"Current setting ('external') is acceptable for dev/test, but ensure:\n"
                        f"- Production uses 'all requests'\n"
                        f"- Internal network is properly secured\n"
                        f"- Access controls prevent unauthorized internal access\n\n"
                        f"**Migration Checklist:**\n"
                        f"- [ ] Verify all internal services can communicate over HTTPS\n"
                        f"- [ ] Update any internal redirect URIs to use https://\n"
                        f"- [ ] Test OAuth flow from internal services\n"
                        f"- [ ] Monitor for connectivity issues after change"
                    ),
                    realm=realm,
                    evidence={
                        "realm": realm.realm,
                        "ssl_required": realm.sslRequired,
                    },
                )
            )

        return findings
