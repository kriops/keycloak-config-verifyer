"""Client authentication security checks."""

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class ConfidentialClientWithoutAuthCheck(SecurityCheck):
    """
    Check if confidential clients lack authentication configuration.

    RFC 6749: Confidential clients MUST authenticate with the authorization server.
    """

    check_id = "KC-AUTH-001"
    check_name = "Confidential Client Without Authentication"
    category = FindingCategory.CLIENT_AUTH
    default_severity = Severity.MEDIUM
    references = [
        "RFC 6749 Section 2.3 - Client Authentication",
        "RFC 6749 Section 3.2.1 - Token Endpoint Authentication",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Only check confidential clients
        if not client.is_confidential:
            return findings

        # Check if authentication is configured
        if not client.has_client_authentication:
            findings.append(
                self.create_finding(
                    title=f"Confidential client '{client.clientId}' lacks authentication",
                    description=(
                        f"The confidential client '{client.clientId}' does not have any "
                        f"authentication method configured.\n\n"
                        f"**What are Confidential Clients?**\n"
                        f"Confidential clients are applications that can securely store credentials "
                        f"(e.g., server-side web applications, backend services). Unlike public clients "
                        f"(browsers, mobile apps), they can authenticate themselves to the authorization server.\n\n"
                        f"**Security Risk:**\n"
                        f"Without authentication, anyone can impersonate this client and:\n"
                        f"1. Exchange authorization codes meant for this client\n"
                        f"2. Request tokens using this client's identity\n"
                        f"3. Access resources the client is authorized to access\n"
                        f"4. Bypass client-specific restrictions or scopes\n\n"
                        f"**RFC 6749 Requirement:**\n"
                        f"Section 2.3 requires confidential clients to authenticate with the "
                        f"authorization server when making requests to the token endpoint.\n\n"
                        f"**Impact:** Client impersonation, unauthorized token issuance, "
                        f"potential data breach if client has elevated privileges."
                    ),
                    remediation=(
                        f"Configure authentication for confidential client '{client.clientId}':\n\n"
                        f"**Step 1: Choose Authentication Method**\n"
                        f"Recommended (in order of preference):\n"
                        f"1. **Private Key JWT** (private_key_jwt) - Most secure, uses asymmetric keys\n"
                        f"2. **Mutual TLS** (tls_client_auth) - Certificate-based authentication\n"
                        f"3. **Client Secret** (client_secret_basic/post) - Acceptable but less secure\n\n"
                        f"**Step 2: Configure in Keycloak**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Credentials tab\n"
                        f"4. Select authentication method:\n\n"
                        f"   **For Client Secret (simpler, but less secure):**\n"
                        f"   - Client Authenticator: 'Client Id and Secret'\n"
                        f"   - Generate or set a strong secret (min 32 characters)\n"
                        f"   - Store secret securely in your application\n\n"
                        f"   **For Private Key JWT (recommended):**\n"
                        f"   - Client Authenticator: 'Signed JWT'\n"
                        f"   - Upload your client's public key or certificate\n"
                        f"   - Client signs JWTs with private key\n\n"
                        f"**Step 3: Update Client Application**\n"
                        f"Ensure your application sends credentials in token requests:\n"
                        f"```\n"
                        f"POST /token\n"
                        f"Authorization: Basic <base64(client_id:client_secret)>\n"
                        f"// OR\n"
                        f"client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\n"
                        f"client_assertion=<signed_jwt>\n"
                        f"```\n\n"
                        f"**Step 4: Test**\n"
                        f"1. Verify token requests without credentials are rejected\n"
                        f"2. Confirm authenticated requests succeed\n"
                        f"3. Test that invalid credentials are rejected"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "confidential": True,
                        "client_authenticator_type": client.clientAuthenticatorType,
                        "has_secret": client.secret is not None,
                        "has_authentication": False,
                    },
                )
            )

        return findings


@security_check
class SymmetricClientAuthenticationCheck(SecurityCheck):
    """
    Check if clients use symmetric authentication (client secrets).

    FAPI 2.0 and best practices recommend asymmetric authentication methods
    for better security.
    """

    check_id = "KC-AUTH-002"
    check_name = "Using Symmetric Client Authentication"
    category = FindingCategory.CLIENT_AUTH
    default_severity = Severity.MEDIUM
    references = [
        "FAPI 2.0 Security Profile - Asymmetric Authentication Required",
        "RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication",
        "OpenID Connect Core - private_key_jwt",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Only check confidential clients
        if not client.is_confidential:
            return findings

        # Check if using symmetric authentication (client secret)
        if client.uses_symmetric_auth:
            findings.append(
                self.create_finding(
                    title=f"Client '{client.clientId}' uses symmetric authentication (client secret)",
                    description=(
                        f"Client '{client.clientId}' uses **symmetric authentication** "
                        f"(client secret), which is less secure than asymmetric methods.\n\n"
                        f"**Symmetric vs. Asymmetric Authentication:**\n\n"
                        f"**Symmetric (Current - Client Secret):**\n"
                        f"- Shared secret stored on both client and server\n"
                        f"- If authorization server is compromised, all secrets are exposed\n"
                        f"- Secret must be transmitted to server for verification\n"
                        f"- Rotating secrets requires coordination\n\n"
                        f"**Asymmetric (Recommended - JWT/mTLS):**\n"
                        f"- Private key stays on client, public key on server\n"
                        f"- Server breach doesn't expose client credentials\n"
                        f"- Client proves possession without transmitting secret\n"
                        f"- Key rotation is easier (update public key only)\n\n"
                        f"**Security Benefits of Asymmetric Methods:**\n"
                        f"1. **Reduced Breach Impact:** If authorization server database is "
                        f"compromised, attackers don't gain usable client credentials\n"
                        f"2. **No Shared Secrets:** Private keys never leave the client\n"
                        f"3. **Better Key Management:** Hardware security modules (HSMs) can "
                        f"protect private keys\n"
                        f"4. **Compliance:** FAPI 2.0 (financial-grade) requires asymmetric auth\n\n"
                        f"**FAPI 2.0 Requirement:**\n"
                        f"Financial-grade API security profile mandates asymmetric client "
                        f"authentication (mTLS or private_key_jwt) for high-security environments.\n\n"
                        f"**Current Setup:**\n"
                        f"- Authentication Type: {client.clientAuthenticatorType or 'client-secret (implicit)'}\n"
                        f"- Has Secret: {client.secret is not None}\n\n"
                        f"**Impact:** If authorization server is compromised, client credentials "
                        f"may be stolen and used to impersonate this client."
                    ),
                    remediation=(
                        f"Migrate client '{client.clientId}' to asymmetric authentication:\n\n"
                        f"**Option 1: Private Key JWT (Recommended for Most Cases)**\n\n"
                        f"Step 1 - Generate Key Pair:\n"
                        f"```bash\n"
                        f"# Generate RSA key pair (2048-bit minimum, 4096-bit recommended)\n"
                        f"openssl genrsa -out client-private-key.pem 4096\n"
                        f"openssl rsa -in client-private-key.pem -pubout -out client-public-key.pem\n\n"
                        f"# Or generate as JWKS\n"
                        f"# Use tools like: https://mkjwk.org/ (2048+ bit RSA)\n"
                        f"```\n\n"
                        f"Step 2 - Configure Keycloak:\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Credentials tab\n"
                        f"4. Client Authenticator: Select 'Signed JWT'\n"
                        f"5. Upload public key or paste JWKS\n"
                        f"6. Click 'Save'\n\n"
                        f"Step 3 - Update Client Application:\n"
                        f"```javascript\n"
                        f"// Create client assertion JWT\n"
                        f"const jwt = {{\n"
                        f"  iss: '{client.clientId}',  // client_id\n"
                        f"  sub: '{client.clientId}',  // client_id\n"
                        f"  aud: 'https://keycloak.example.com/realms/{realm.realm}/protocol/openid-connect/token',\n"
                        f"  jti: crypto.randomUUID(),  // unique JWT ID\n"
                        f"  exp: Math.floor(Date.now() / 1000) + 60,  // 1 minute expiry\n"
                        f"  iat: Math.floor(Date.now() / 1000)\n"
                        f"}};\n\n"
                        f"// Sign with private key\n"
                        f"const signedJWT = signJWT(jwt, privateKey, 'RS256');\n\n"
                        f"// Token request\n"
                        f"const response = await fetch('/token', {{\n"
                        f"  method: 'POST',\n"
                        f"  body: new URLSearchParams({{\n"
                        f"    grant_type: 'authorization_code',\n"
                        f"    code: authCode,\n"
                        f"    redirect_uri: redirectUri,\n"
                        f"    client_id: '{client.clientId}',\n"
                        f"    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',\n"
                        f"    client_assertion: signedJWT\n"
                        f"  }})\n"
                        f"}});\n"
                        f"```\n\n"
                        f"**Option 2: Mutual TLS (mTLS)**\n"
                        f"- Requires certificate infrastructure\n"
                        f"- Client presents X.509 certificate during TLS handshake\n"
                        f"- More complex but provides transport-layer security\n"
                        f"- Suitable for enterprise environments with PKI\n\n"
                        f"**Migration Strategy:**\n"
                        f"1. Generate and configure asymmetric authentication\n"
                        f"2. Test new authentication method in staging\n"
                        f"3. Update production clients gradually\n"
                        f"4. Remove client secret after migration complete\n\n"
                        f"**Security Note:** Store private keys securely:\n"
                        f"- Use environment variables or secret management systems\n"
                        f"- Never commit private keys to source control\n"
                        f"- Consider hardware security modules (HSMs) for production\n"
                        f"- Rotate keys periodically (e.g., annually)"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "authentication_type": client.clientAuthenticatorType or "client-secret",
                        "uses_symmetric_auth": True,
                        "has_secret": client.secret is not None,
                    },
                )
            )

        return findings
