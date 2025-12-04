"""Token security checks."""

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class ExcessiveTokenLifespanCheck(SecurityCheck):
    """
    Check for excessive access token lifespans.

    RFC 9700: Access tokens SHOULD have short lifespans to limit impact of theft.
    Recommended: 5-15 minutes (300-900 seconds).
    """

    check_id = "KC-TOKEN-001"
    check_name = "Excessive Access Token Lifespan"
    category = FindingCategory.TOKEN_SECURITY
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 Section 4.3 - Token Lifespans",
        "OAuth 2.0 Security Best Practices",
    ]

    # Threshold: tokens over 15 minutes (900 seconds) are excessive
    MAX_RECOMMENDED_LIFESPAN = 900

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        if realm.accessTokenLifespan > self.MAX_RECOMMENDED_LIFESPAN:
            findings.append(
                self.create_finding(
                    title=f"Excessive access token lifespan in realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' has an access token lifespan of "
                        f"**{realm.accessTokenLifespan} seconds** "
                        f"({realm.accessTokenLifespan // 60} minutes), which exceeds "
                        f"the recommended maximum of {self.MAX_RECOMMENDED_LIFESPAN} seconds "
                        f"(15 minutes).\n\n"
                        f"**Security Impact:**\n"
                        f"1. **Increased Attack Window:** Stolen tokens remain valid longer\n"
                        f"2. **Delayed Revocation:** Compromised accounts stay accessible\n"
                        f"3. **Greater Damage Potential:** Attackers have more time to exploit access\n\n"
                        f"**Attack Scenario:**\n"
                        f"- Attacker steals access token (XSS, network interception, etc.)\n"
                        f"- With long lifespan, attacker has extended time to:\n"
                        f"  - Extract sensitive data\n"
                        f"  - Perform unauthorized actions\n"
                        f"  - Pivot to other systems\n"
                        f"- Even if breach is detected, token remains valid\n\n"
                        f"**Best Practice:**\n"
                        f"- Short-lived access tokens: 5-15 minutes (300-900 seconds)\n"
                        f"- Use refresh tokens for long-lived sessions\n"
                        f"- Implement token revocation for compromised tokens"
                    ),
                    remediation=(
                        f"Reduce access token lifespan for realm '{realm.realm}':\n\n"
                        f"**Step 1: Update Realm Settings**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: Tokens tab\n"
                        f"4. Set 'Access Token Lifespan' to: **5-15 minutes**\n"
                        f"   - Recommended: 5 minutes (300 seconds)\n"
                        f"   - Maximum: 15 minutes (900 seconds)\n"
                        f"   - Current: {realm.accessTokenLifespan} seconds (TOO LONG)\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 2: Implement Token Refresh**\n"
                        f"Ensure clients use refresh tokens for long-lived sessions:\n"
                        f"```javascript\n"
                        f"// When access token expires (5-15 min):\n"
                        f"async function refreshAccessToken() {{\n"
                        f"  const response = await fetch('/token', {{\n"
                        f"    method: 'POST',\n"
                        f"    body: new URLSearchParams({{\n"
                        f"      grant_type: 'refresh_token',\n"
                        f"      refresh_token: storedRefreshToken\n"
                        f"    }})\n"
                        f"  }});\n"
                        f"  const {{ access_token }} = await response.json();\n"
                        f"  return access_token;\n"
                        f"}}\n"
                        f"```\n\n"
                        f"**Step 3: Proactive Token Refresh**\n"
                        f"Refresh tokens before expiration (e.g., 1 minute before):\n"
                        f"- Prevents user interruption\n"
                        f"- Maintains seamless session\n"
                        f"- Keeps tokens short-lived\n\n"
                        f"**Step 4: Testing**\n"
                        f"1. Verify tokens expire after configured time\n"
                        f"2. Test refresh token flow works correctly\n"
                        f"3. Confirm user experience remains smooth"
                    ),
                    realm=realm,
                    evidence={
                        "realm": realm.realm,
                        "access_token_lifespan": realm.accessTokenLifespan,
                        "access_token_lifespan_minutes": realm.accessTokenLifespan // 60,
                        "recommended_max": self.MAX_RECOMMENDED_LIFESPAN,
                    },
                )
            )

        return findings


@security_check
class RefreshTokenReuseCheck(SecurityCheck):
    """
    Check if refresh token reuse is allowed.

    RFC 9700: Refresh token rotation SHOULD be implemented for public clients.
    """

    check_id = "KC-TOKEN-002"
    check_name = "Refresh Token Reuse Allowed"
    category = FindingCategory.TOKEN_SECURITY
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 Section 4.3.3 - Refresh Token Rotation",
        "OAuth 2.1 - Refresh Token Protection",
    ]

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        if not realm.refresh_token_rotation_enabled:
            findings.append(
                self.create_finding(
                    title=f"Refresh token reuse allowed in realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' allows refresh tokens to be reused "
                        f"**{realm.refreshTokenMaxReuse} times**, which increases security risk.\n\n"
                        f"**Current Configuration:**\n"
                        f"- refreshTokenMaxReuse: {realm.refreshTokenMaxReuse}\n"
                        f"- Recommended: 0 (no reuse - automatic rotation)\n\n"
                        f"**Security Benefits of Rotation:**\n\n"
                        f"1. **Theft Detection:** If a stolen refresh token is used, the legitimate "
                        f"client's token becomes invalid, alerting the system to compromise\n\n"
                        f"2. **Automatic Revocation:** When token reuse is detected, all tokens "
                        f"for that grant can be revoked automatically\n\n"
                        f"3. **Reduced Attack Window:** Each refresh token is single-use, "
                        f"limiting attacker opportunities\n\n"
                        f"4. **Compliance:** OAuth 2.1 and RFC 9700 strongly recommend rotation "
                        f"for public clients\n\n"
                        f"**How Rotation Detects Theft:**\n"
                        f"- Legitimate client uses refresh token → gets new token\n"
                        f"- Old refresh token is invalidated\n"
                        f"- If attacker tries to use old token → System detects reuse attempt\n"
                        f"- System revokes entire token family, blocking both attacker and user\n"
                        f"- User must re-authenticate (indicates potential compromise)\n\n"
                        f"**Without Rotation:**\n"
                        f"- Stolen refresh token works indefinitely\n"
                        f"- No detection mechanism\n"
                        f"- Attacker maintains persistent access"
                    ),
                    remediation=(
                        f"Enable refresh token rotation for realm '{realm.realm}':\n\n"
                        f"**Step 1: Update Realm Settings**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: Tokens tab\n"
                        f"4. Set 'Refresh Token Max Reuse' to: **0**\n"
                        f"   - 0 = Automatic rotation (RECOMMENDED)\n"
                        f"   - Current: {realm.refreshTokenMaxReuse} (allows reuse)\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 2: Update Client Implementation**\n"
                        f"Handle refresh token rotation in your application:\n"
                        f"```javascript\n"
                        f"async function refreshTokens() {{\n"
                        f"  const response = await fetch('/token', {{\n"
                        f"    method: 'POST',\n"
                        f"    body: new URLSearchParams({{\n"
                        f"      grant_type: 'refresh_token',\n"
                        f"      refresh_token: currentRefreshToken,\n"
                        f"      client_id: 'your-client-id'\n"
                        f"    }})\n"
                        f"  }});\n\n"
                        f"  const tokens = await response.json();\n"
                        f"  \n"
                        f"  // IMPORTANT: Store NEW refresh token\n"
                        f"  currentRefreshToken = tokens.refresh_token; // <-- Rotated token\n"
                        f"  currentAccessToken = tokens.access_token;\n"
                        f"  \n"
                        f"  return tokens;\n"
                        f"}}\n"
                        f"```\n\n"
                        f"**Step 3: Error Handling**\n"
                        f"Detect reuse attempts (indicates compromise):\n"
                        f"```javascript\n"
                        f"if (response.status === 400 && error === 'invalid_grant') {{\n"
                        f"  // Refresh token was invalidated (possible theft detected)\n"
                        f"  // Force user to re-authenticate\n"
                        f"  redirectToLogin();\n"
                        f"}}\n"
                        f"```\n\n"
                        f"**Step 4: Testing**\n"
                        f"1. Verify new refresh token returned with each refresh\n"
                        f"2. Test that old refresh tokens are rejected\n"
                        f"3. Confirm reuse attempt revokes entire token family"
                    ),
                    realm=realm,
                    evidence={
                        "realm": realm.realm,
                        "refresh_token_max_reuse": realm.refreshTokenMaxReuse,
                        "rotation_enabled": realm.refresh_token_rotation_enabled,
                    },
                )
            )

        return findings


@security_check
class FullScopeAllowedCheck(SecurityCheck):
    """
    Check if clients have full scope allowed.

    Best Practice: Limit scope to minimum required resources (principle of least privilege).
    """

    check_id = "KC-TOKEN-003"
    check_name = "Full Scope Allowed"
    category = FindingCategory.TOKEN_SECURITY
    default_severity = Severity.MEDIUM
    references = [
        "RFC 9700 Section 4.3.1 - Token Privilege Restriction",
        "Principle of Least Privilege",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        if client.fullScopeAllowed:
            findings.append(
                self.create_finding(
                    title=f"Full scope allowed for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has **full scope allowed**, granting "
                        f"access to ALL roles and permissions in the realm.\n\n"
                        f"**Security Concern:**\n"
                        f"Violates the **principle of least privilege**. If this client is "
                        f"compromised, attackers gain access to all realm resources, not just "
                        f"what the client actually needs.\n\n"
                        f"**Best Practice:**\n"
                        f"Limit scope to only the roles and permissions the client requires:\n"
                        f"- If client needs user profile: grant 'profile' scope only\n"
                        f"- If client needs email: grant 'email' scope only\n"
                        f"- If client needs specific API access: grant only those scopes\n\n"
                        f"**Impact if Compromised:**\n"
                        f"- With full scope: Attacker accesses ALL realm resources\n"
                        f"- With limited scope: Attacker only accesses specific permissions\n\n"
                        f"**Severity:** Medium (defense-in-depth concern, not immediately exploitable)"
                    ),
                    remediation=(
                        f"Restrict scope for client '{client.clientId}':\n\n"
                        f"**Step 1: Identify Required Scopes**\n"
                        f"Determine what this client actually needs:\n"
                        f"- User profile data? → 'profile' scope\n"
                        f"- Email address? → 'email' scope\n"
                        f"- Specific API resources? → Custom scopes\n\n"
                        f"**Step 2: Disable Full Scope**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Client Scopes tab\n"
                        f"4. Toggle OFF 'Full Scope Allowed'\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 3: Assign Specific Scopes**\n"
                        f"1. In 'Client Scopes' tab\n"
                        f"2. Click 'Add client scope'\n"
                        f"3. Select required scopes (e.g., 'profile', 'email')\n"
                        f"4. Choose 'Default' or 'Optional'\n\n"
                        f"**Step 4: Assign Required Roles**\n"
                        f"1. Go to: Scope tab\n"
                        f"2. Add specific realm roles or client roles needed\n\n"
                        f"**Step 5: Testing**\n"
                        f"1. Authenticate with the client\n"
                        f"2. Inspect access token claims\n"
                        f"3. Verify only required scopes/roles are present\n"
                        f"4. Test that client functionality still works"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "full_scope_allowed": True,
                    },
                )
            )

        return findings


@security_check
class BearerTokensNotSenderConstrainedCheck(SecurityCheck):
    """
    Check if bearer tokens are not sender-constrained.

    RFC 9700: Bearer tokens SHOULD be sender-constrained using DPoP (RFC 9449)
    or mTLS (RFC 8705) to prevent token theft and replay attacks.
    """

    check_id = "KC-TOKEN-005"
    check_name = "Bearer Tokens Not Sender-Constrained"
    category = FindingCategory.TOKEN_SECURITY
    default_severity = Severity.HIGH
    references = [
        "RFC 9700 - Sender-Constrained Tokens",
        "RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)",
        "RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens",
        "Cloudflare/Okta Breach (November 2023) - Unrotated bearer token",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Check for DPoP or mTLS token binding
        has_dpop = self._has_dpop_enabled(client)
        has_mtls_binding = self._has_mtls_token_binding(client)

        if not has_dpop and not has_mtls_binding:
            findings.append(
                self.create_finding(
                    title=f"Bearer tokens not sender-constrained for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' uses **bearer tokens without sender-constraining**, "
                        f"making stolen tokens fully reusable by attackers.\n\n"
                        f"**What Are Bearer Tokens?**\n"
                        f'Bearer tokens are like "keys" that grant access to resources. Whoever '
                        f'possesses the token can use it ("bearer" = holder). This makes them '
                        f"vulnerable if stolen.\n\n"
                        f"**What Is Sender-Constraining?**\n"
                        f"Sender-constraining binds tokens to the client that obtained them, "
                        f"making stolen tokens useless to attackers. Two methods:\n\n"
                        f"1. **DPoP (Demonstrating Proof-of-Possession, RFC 9449):**\n"
                        f"   - Client generates key pair\n"
                        f"   - Token bound to client's public key\n"
                        f"   - Client must prove possession of private key with each request\n"
                        f"   - Stolen tokens can't be used without private key\n\n"
                        f"2. **mTLS Certificate-Bound Tokens (RFC 8705):**\n"
                        f"   - Token bound to client's TLS certificate\n"
                        f"   - Client must present same certificate for each request\n"
                        f"   - Stolen tokens can't be used without certificate\n\n"
                        f"**Security Impact Without Sender-Constraining:**\n\n"
                        f"**Attack Scenario: Token Theft**\n"
                        f"1. Attacker steals access token via:\n"
                        f"   - Network interception (compromised TLS)\n"
                        f"   - Database breach (token storage)\n"
                        f"   - Log file exposure\n"
                        f"   - Memory dump\n"
                        f"   - XSS attack\n"
                        f"2. Attacker uses stolen token immediately\n"
                        f"3. No proof of possession required\n"
                        f"4. **Full access until token expires**\n\n"
                        f"**Real-World Breach:**\n"
                        f"**Cloudflare via Okta (November 2023):**\n"
                        f"- Attacker stole bearer access token from Okta\n"
                        f"- Token not sender-constrained, fully reusable\n"
                        f"- Token not rotated after compromise\n"
                        f"- Attacker maintained persistent access to Cloudflare systems\n"
                        f"- Breach: Internal wikis, bug database, source code repositories\n\n"
                        f"**GitHub Personal Access Token Theft (December 2022):**\n"
                        f"- Stolen bearer PATs bypassed 2FA\n"
                        f"- No binding to originating device\n"
                        f"- Attackers accessed private repositories\n\n"
                        f"**RFC 9700 Recommendation:**\n"
                        f'"Authorization servers SHOULD use mechanisms for sender-constraining '
                        f'access tokens to mitigate the risk of token theft and replay."\n\n'
                        f"**Current Configuration:**\n"
                        f"- DPoP Enabled: No\n"
                        f"- mTLS Token Binding: No\n"
                        f'- **Result:** Tokens are "golden tickets" - steal once, use anywhere'
                    ),
                    remediation=(
                        f"Implement sender-constrained tokens for client '{client.clientId}':\n\n"
                        f"**Option 1: DPoP (Recommended for Most Cases)**\n\n"
                        f"DPoP is easier to implement and doesn't require certificate infrastructure.\n\n"
                        f"**Step 1: Enable DPoP in Keycloak**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Advanced tab\n"
                        f"4. Look for: OAuth 2.0 DPoP Bound Access Tokens\n"
                        f"5. Enable: 'DPoP Required' or 'DPoP Optional'\n"
                        f"6. Click 'Save'\n\n"
                        f"**Step 2: Client Implementation - Generate Key Pair**\n"
                        f"```javascript\n"
                        f"// Generate key pair (do this once, store private key securely)\n"
                        f"const keyPair = await crypto.subtle.generateKey(\n"
                        f"  {{\n"
                        f"    name: 'RSASSA-PKCS1-v1_5',\n"
                        f"    modulusLength: 2048,\n"
                        f"    publicExponent: new Uint8Array([1, 0, 1]),\n"
                        f"    hash: 'SHA-256',\n"
                        f"  }},\n"
                        f"  true,\n"
                        f"  ['sign', 'verify']\n"
                        f");\n"
                        f"```\n\n"
                        f"**Step 3: Create DPoP Proof for Token Request**\n"
                        f"```javascript\n"
                        f"const dpopProof = await createDPoPProof({{\n"
                        f"  keyPair,\n"
                        f"  htm: 'POST',  // HTTP method\n"
                        f"  htu: 'https://keycloak.example.com/realms/{realm.realm}/protocol/openid-connect/token',\n"
                        f"  jti: crypto.randomUUID(),  // Unique request ID\n"
                        f"}});\n\n"
                        f"// Token request with DPoP\n"
                        f"const response = await fetch('/token', {{\n"
                        f"  method: 'POST',\n"
                        f"  headers: {{\n"
                        f"    'DPoP': dpopProof,\n"
                        f"    'Content-Type': 'application/x-www-form-urlencoded',\n"
                        f"  }},\n"
                        f"  body: new URLSearchParams({{\n"
                        f"    grant_type: 'authorization_code',\n"
                        f"    code: authCode,\n"
                        f"    redirect_uri: redirectUri,\n"
                        f"  }})\n"
                        f"}});\n"
                        f"```\n\n"
                        f"**Step 4: Use DPoP Proof with Access Token**\n"
                        f"```javascript\n"
                        f"// Create DPoP proof for API request\n"
                        f"const apiDPoPProof = await createDPoPProof({{\n"
                        f"  keyPair,\n"
                        f"  htm: 'GET',\n"
                        f"  htu: 'https://api.example.com/user/profile',\n"
                        f"  ath: sha256Hash(accessToken),  // Hash of access token\n"
                        f"  jti: crypto.randomUUID(),\n"
                        f"}});\n\n"
                        f"// API request with DPoP-bound token\n"
                        f"const apiResponse = await fetch('https://api.example.com/user/profile', {{\n"
                        f"  headers: {{\n"
                        f"    'Authorization': `DPoP ${{accessToken}}`,  // Note: 'DPoP' not 'Bearer'\n"
                        f"    'DPoP': apiDPoPProof,\n"
                        f"  }}\n"
                        f"}});\n"
                        f"```\n\n"
                        f"**Option 2: mTLS Certificate-Bound Tokens**\n\n"
                        f"Suitable for enterprise environments with PKI infrastructure.\n\n"
                        f"1. Enable mTLS in Keycloak (Realm Settings → Tokens → Certificate-Bound Tokens)\n"
                        f"2. Configure client certificate validation\n"
                        f"3. Clients present X.509 certificate with each request\n"
                        f"4. Tokens bound to certificate thumbprint\n\n"
                        f"**Benefits:**\n"
                        f"- ✅ Stolen tokens can't be used without private key/certificate\n"
                        f"- ✅ Prevents token replay attacks\n"
                        f"- ✅ Mitigates impact of token leakage\n"
                        f"- ✅ Required for FAPI 2.0 compliance\n\n"
                        f"**Testing:**\n"
                        f"1. Obtain access token with DPoP/mTLS\n"
                        f"2. Try using token WITHOUT proof → Should fail\n"
                        f"3. Try using token WITH correct proof → Should succeed\n"
                        f"4. Try using token with DIFFERENT key → Should fail\n\n"
                        f"**Libraries:**\n"
                        f"- JavaScript: `dpop` npm package\n"
                        f"- Python: `authlib` with DPoP support\n"
                        f"- Java: `nimbus-jose-jwt` library"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "dpop_enabled": has_dpop,
                        "mtls_token_binding": has_mtls_binding,
                        "sender_constrained": False,
                    },
                )
            )

        return findings

    def _has_dpop_enabled(self, client: ClientConfig) -> bool:
        """Check if DPoP (Demonstrating Proof-of-Possession) is enabled."""
        # Keycloak stores DPoP config in attributes
        dpop_bound = client.attributes.get("dpop.bound.access.tokens", "").lower()
        return dpop_bound in ["true", "required"]

    def _has_mtls_token_binding(self, client: ClientConfig) -> bool:
        """Check if mTLS certificate-bound tokens are enabled."""
        # Keycloak stores mTLS token binding in attributes
        mtls_binding = client.attributes.get(
            "tls.client.certificate.bound.access.tokens", ""
        ).lower()
        return mtls_binding == "true"
