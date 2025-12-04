"""OAuth flow security checks."""

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class ImplicitFlowEnabledCheck(SecurityCheck):
    """
    Check if implicit flow is enabled.

    RFC 9700 Section 4.1.2: The implicit grant (response_type=token) SHOULD NOT be used.
    Access tokens exposed in URLs leak through browser history, Referer headers, and
    server logs.
    """

    check_id = "KC-FLOW-001"
    check_name = "Implicit Flow Enabled"
    category = FindingCategory.OAUTH_FLOWS
    default_severity = Severity.CRITICAL
    references = [
        "RFC 9700 Section 4.1.2 - Implicit Grant Deprecated",
        "OAuth 2.1 - Implicit Grant Removed",
        "Proofpoint Research 2023 - OAuth Phishing Attacks",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        if client.implicitFlowEnabled:
            findings.append(
                self.create_finding(
                    title=f"Implicit flow enabled for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has the **implicit grant flow** enabled, "
                        f"which is **deprecated and insecure**.\n\n"
                        f"**Why Implicit Flow is Dangerous:**\n"
                        f"1. **Token Exposure in URLs:** Access tokens appear in URL fragments "
                        f"(#access_token=...), which leak through:\n"
                        f"   - Browser history (permanent record)\n"
                        f"   - Referer headers (sent to third parties)\n"
                        f"   - Server logs and analytics\n"
                        f"   - Browser extensions with URL access\n\n"
                        f"2. **No Sender-Constraining:** Cannot bind tokens to specific clients, "
                        f"making stolen tokens immediately usable\n\n"
                        f"3. **Token Injection Attacks:** Attackers can inject stolen tokens "
                        f"into victim sessions\n\n"
                        f"4. **No Refresh Mechanism:** Long-lived tokens increase attack window\n\n"
                        f"**Real-World Impact:**\n"
                        f"- Proofpoint Research (2023) documented large-scale phishing attacks "
                        f"exploiting Microsoft OAuth with URL manipulation\n"
                        f"- Implicit flow's URL-based token delivery enables covert redirection attacks\n\n"
                        f"**RFC 9700 Mandate:** The implicit grant SHOULD NOT be used. "
                        f"OAuth 2.1 removes it entirely from the specification."
                    ),
                    remediation=(
                        f"Migrate client '{client.clientId}' from implicit flow to authorization code + PKCE:\n\n"
                        f"**Step 1: Keycloak Configuration**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. **Disable** 'Implicit Flow Enabled'\n"
                        f"5. **Enable** 'Standard Flow Enabled' (authorization code)\n"
                        f"6. Go to: Advanced Settings tab\n"
                        f"7. Set 'Proof Key for Code Exchange Code Challenge Method' to 'S256'\n"
                        f"8. Click 'Save'\n\n"
                        f"**Step 2: Update Client Application**\n"
                        f"Replace implicit flow implementation:\n"
                        f"```javascript\n"
                        f"// OLD (Implicit - REMOVE):\n"
                        f"// response_type=token\n"
                        f"// Tokens in URL fragment\n\n"
                        f"// NEW (Authorization Code + PKCE):\n"
                        f"const codeVerifier = generateCodeVerifier();\n"
                        f"const codeChallenge = await sha256(codeVerifier);\n"
                        f"// response_type=code&code_challenge=...&code_challenge_method=S256\n"
                        f"// Exchange code for token at /token endpoint\n"
                        f"```\n\n"
                        f"**Step 3: Testing**\n"
                        f"1. Verify tokens no longer appear in URL\n"
                        f"2. Confirm PKCE code_challenge in authorization requests\n"
                        f"3. Test token exchange at /token endpoint\n\n"
                        f"**Migration Timeline:** Prioritize this change - CRITICAL severity."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "implicit_flow_enabled": True,
                        "standard_flow_enabled": client.standardFlowEnabled,
                        "public_client": client.is_public,
                    },
                )
            )

        return findings


@security_check
class PasswordGrantEnabledCheck(SecurityCheck):
    """
    Check if password grant (direct access grants) is enabled.

    RFC 9700 Section 4.1.3: Resource owner password credentials grant MUST NOT be used.
    This flow exposes user credentials directly to client applications.
    """

    check_id = "KC-FLOW-003"
    check_name = "Password Grant Enabled"
    category = FindingCategory.OAUTH_FLOWS
    default_severity = Severity.CRITICAL
    references = [
        "RFC 9700 Section 4.1.3 - Password Grant Forbidden",
        "OAuth 2.1 - Resource Owner Password Removed",
        "OWASP OAuth Cheat Sheet",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        if client.directAccessGrantsEnabled:
            findings.append(
                self.create_finding(
                    title=f"Password grant (direct access) enabled for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has **Resource Owner Password Credentials Grant** "
                        f"(direct access grants) enabled, which is **forbidden by RFC 9700**.\n\n"
                        f"**Critical Security Issues:**\n\n"
                        f"1. **Credential Exposure:** Users enter passwords directly into the client "
                        f"application, not the authorization server:\n"
                        f"   - Credentials can leak from client storage\n"
                        f"   - Credentials appear in client logs\n"
                        f"   - Credentials vulnerable during client transmission\n"
                        f"   - No control over client's credential handling\n\n"
                        f"2. **Enables Phishing:** Trains users to enter credentials outside the "
                        f"authorization server, making phishing attacks easier\n\n"
                        f"3. **Breaks Security Features:**\n"
                        f"   - Incompatible with multi-factor authentication (MFA)\n"
                        f"   - Cannot use modern cryptographic authentication (WebAuthn, FIDO2)\n"
                        f"   - Cannot be bound to specific web origins\n"
                        f"   - Bypasses authorization server security policies\n\n"
                        f"4. **Increased Attack Surface:** Client becomes a high-value target "
                        f"for credential theft\n\n"
                        f"**RFC 9700 Mandate:** The resource owner password credentials grant "
                        f"MUST NOT be used. OAuth 2.1 removes it entirely."
                    ),
                    remediation=(
                        f"Disable password grant for client '{client.clientId}':\n\n"
                        f"**Step 1: Keycloak Configuration**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. **Disable** 'Direct Access Grants Enabled'\n"
                        f"5. **Enable** 'Standard Flow Enabled' (if not already enabled)\n"
                        f"6. Click 'Save'\n\n"
                        f"**Step 2: Migrate to Authorization Code Flow**\n"
                        f"Replace password grant with browser-based authorization:\n"
                        f"```javascript\n"
                        f"// OLD (Password Grant - REMOVE):\n"
                        f"// POST /token\n"
                        f"// grant_type=password&username=USER&password=PASS\n\n"
                        f"// NEW (Authorization Code + PKCE):\n"
                        f"// 1. Redirect to /authorize with code_challenge\n"
                        f"// 2. User authenticates at authorization server (NOT in your app)\n"
                        f"// 3. Exchange code for token at /token endpoint\n"
                        f"```\n\n"
                        f"**Step 3: For Native/Mobile Apps**\n"
                        f"Use system browser with custom URI scheme or localhost:\n"
                        f"- iOS: ASWebAuthenticationSession\n"
                        f"- Android: Custom Tabs\n"
                        f"- Desktop: Launch system browser\n\n"
                        f"**Step 4: Communication**\n"
                        f"Notify users of the authentication flow change. The new flow is more "
                        f"secure and supports MFA.\n\n"
                        f"**Important:** Do NOT collect usernames/passwords in your application. "
                        f"Always redirect to Keycloak."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "direct_access_grants_enabled": True,
                        "standard_flow_enabled": client.standardFlowEnabled,
                        "public_client": client.is_public,
                    },
                )
            )

        return findings
