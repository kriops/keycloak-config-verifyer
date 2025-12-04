"""PKCE (Proof Key for Code Exchange) security checks."""

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class PKCENotEnforcedCheck(SecurityCheck):
    """
    Check if PKCE is enforced for public clients.

    RFC 9700 Section 3.1: Authorization servers MUST enforce PKCE for
    all public clients. PKCE with S256 challenge method prevents
    authorization code interception attacks.
    """

    check_id = "KC-PKCE-001"
    check_name = "PKCE Not Enforced"
    category = FindingCategory.PKCE
    default_severity = Severity.CRITICAL
    references = [
        "RFC 9700 Section 3.1 - PKCE Mandatory",
        "RFC 7636 - Proof Key for Code Exchange",
        "OAuth 2.1 Draft - PKCE Required",
        "CVE-2023-28131 - Expo PKCE bypass",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Only check public clients using authorization code flow
        if not client.is_public:
            return findings

        if not client.standardFlowEnabled:
            return findings

        # Check for PKCE configuration
        pkce_method = client.pkce_method

        if not pkce_method:
            findings.append(
                self.create_finding(
                    title=f"PKCE not enforced for public client '{client.clientId}'",
                    description=(
                        f"The public client '{client.clientId}' does not enforce PKCE "
                        f"(Proof Key for Code Exchange). RFC 9700 mandates PKCE for ALL "
                        f"OAuth 2.0 clients, especially public clients which cannot securely "
                        f"store credentials.\n\n"
                        f"Without PKCE, authorization codes can be intercepted by attackers "
                        f"and exchanged for access tokens. This is a critical vulnerability "
                        f"that enables account takeover attacks.\n\n"
                        f"**Attack Scenario:**\n"
                        f"1. Attacker intercepts authorization code from redirect URI\n"
                        f"2. Attacker exchanges code for access token at /token endpoint\n"
                        f"3. Attacker gains full access to user's account\n\n"
                        f"**Impact:** Authorization code interception, session hijacking, "
                        f"account takeover, data breach."
                    ),
                    remediation=(
                        f"Enable PKCE with S256 method for client '{client.clientId}':\n\n"
                        f"**Keycloak Configuration:**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Advanced Settings tab\n"
                        f"4. Find: 'Proof Key for Code Exchange Code Challenge Method'\n"
                        f"5. Select: 'S256' (SHA-256)\n"
                        f"6. Click 'Save'\n\n"
                        f"**Client Implementation:**\n"
                        f"1. Generate cryptographically random code_verifier (43-128 chars)\n"
                        f"   Example: crypto.randomBytes(32).toString('base64url')\n"
                        f"2. Compute code_challenge = BASE64URL(SHA256(code_verifier))\n"
                        f"3. Include in authorization request:\n"
                        f"   - code_challenge=<computed-value>\n"
                        f"   - code_challenge_method=S256\n"
                        f"4. Include code_verifier in token request\n\n"
                        f"**Verification:**\n"
                        f"Test the flow and confirm authorization fails without valid code_verifier."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "public_client": True,
                        "standard_flow_enabled": client.standardFlowEnabled,
                        "pkce_method": None,
                        "attributes": client.attributes,
                    },
                )
            )

        return findings


@security_check
class PKCEWeakMethodCheck(SecurityCheck):
    """
    Check if PKCE uses weak 'plain' method instead of S256.

    RFC 9700 requires the S256 challenge method. The 'plain' method
    exposes the code_verifier in the authorization request, breaking
    the security model.
    """

    check_id = "KC-PKCE-002"
    check_name = "Weak PKCE Method (plain)"
    category = FindingCategory.PKCE
    default_severity = Severity.CRITICAL
    references = [
        "RFC 9700 Section 3.1",
        "RFC 7636 - S256 Required",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Only check clients with authorization code flow
        if not client.standardFlowEnabled:
            return findings

        pkce_method = client.pkce_method

        if pkce_method and pkce_method != "S256":
            findings.append(
                self.create_finding(
                    title=f"Weak PKCE method '{pkce_method}' for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' uses PKCE challenge method '{pkce_method}' "
                        f"instead of the required 'S256' method.\n\n"
                        f"RFC 9700 mandates the S256 challenge method which uses SHA-256 hashing. "
                        f"The 'plain' method exposes the code_verifier directly in the authorization "
                        f"request (since code_challenge = code_verifier), breaking the security model.\n\n"
                        f"**Vulnerability:**\n"
                        f"An attacker observing the authorization request can extract the verifier "
                        f"and use it to exchange intercepted authorization codes.\n\n"
                        f"**Attack Scenario:**\n"
                        f"1. Attacker intercepts authorization request (e.g., via network MitM)\n"
                        f"2. Attacker extracts code_challenge (which equals code_verifier in plain mode)\n"
                        f"3. Attacker intercepts authorization code from callback\n"
                        f"4. Attacker uses the verifier to exchange code for tokens\n\n"
                        f"**Impact:** Reduced PKCE effectiveness, potential authorization code "
                        f"interception, account takeover."
                    ),
                    remediation=(
                        f"Update PKCE method to S256 for client '{client.clientId}':\n\n"
                        f"**Keycloak Configuration:**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Advanced Settings tab\n"
                        f"4. Change 'Proof Key for Code Exchange Code Challenge Method' to 'S256'\n"
                        f"5. Click 'Save'\n\n"
                        f"**Client Implementation Update:**\n"
                        f"Ensure client application uses SHA-256 hashing:\n"
                        f"  code_challenge = BASE64URL(SHA256(code_verifier))\n"
                        f"  // NOT: code_challenge = code_verifier\n\n"
                        f"**Testing:**\n"
                        f"Verify authorization requests include code_challenge_method=S256"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "current_method": pkce_method,
                        "required_method": "S256",
                    },
                )
            )

        return findings


@security_check
class PKCEOptionalForConfidentialCheck(SecurityCheck):
    """
    Recommend PKCE even for confidential clients.

    While RFC 9700 mandates PKCE for public clients, it's also
    recommended for confidential clients as defense-in-depth.
    """

    check_id = "KC-PKCE-003"
    check_name = "PKCE Optional for Confidential Client"
    category = FindingCategory.PKCE
    default_severity = Severity.MEDIUM
    references = [
        "RFC 9700 Section 3.1 - Best Practice",
        "OAuth 2.1 - Defense in Depth",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Check confidential clients
        if not client.is_confidential:
            return findings

        if not client.standardFlowEnabled:
            return findings

        if not client.pkce_enabled:
            findings.append(
                self.create_finding(
                    title=f"PKCE not enabled for confidential client '{client.clientId}'",
                    description=(
                        "While RFC 9700 mandates PKCE for public clients, it's also "
                        "**strongly recommended** for confidential clients as a defense-in-depth measure.\n\n"
                        "**Benefits of PKCE for Confidential Clients:**\n"
                        "1. Additional protection against authorization code interception\n"
                        "2. Defense if client secret is compromised or leaked\n"
                        "3. Protection in misconfigured environments\n"
                        "4. Aligns with OAuth 2.1 best practices\n\n"
                        "PKCE provides layered security even when client secrets are used, "
                        "protecting against authorization code interception in compromised "
                        "environments or misconfigurations.\n\n"
                        "**Impact (Medium):** Reduced defense-in-depth, potential vulnerability "
                        "if client secret is compromised or environment is misconfigured."
                    ),
                    remediation=(
                        f"Enable PKCE for confidential client '{client.clientId}':\n\n"
                        f"**Keycloak Configuration:**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Advanced Settings tab\n"
                        f"4. Set 'Proof Key for Code Exchange Code Challenge Method' to 'S256'\n"
                        f"5. Click 'Save'\n\n"
                        f"**Client Implementation:**\n"
                        f"Update client application to implement PKCE flow:\n"
                        f"1. Generate code_verifier before each authorization request\n"
                        f"2. Compute code_challenge using SHA-256\n"
                        f"3. Include both code_challenge and client_secret in respective requests\n\n"
                        f"**Note:** PKCE complements client secret authentication; both should be used."
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "confidential_client": True,
                        "pkce_enabled": False,
                        "client_authenticator_type": client.clientAuthenticatorType,
                    },
                )
            )

        return findings
