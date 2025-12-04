"""Miscellaneous security checks (Low and Info severity)."""

from ..models import ClientConfig, Finding, FindingCategory, RealmConfig, Severity
from .base import SecurityCheck, security_check


@security_check
class BruteForceProtectionDisabledCheck(SecurityCheck):
    """
    Check if brute force protection is disabled for the realm.

    Brute force protection helps prevent password guessing attacks.
    """

    check_id = "KC-SEC-001"
    check_name = "Brute Force Protection Disabled"
    category = FindingCategory.MISC
    default_severity = Severity.LOW
    references = [
        "OWASP - Brute Force Attack Prevention",
        "Keycloak Security Best Practices",
    ]

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        if not realm.bruteForceProtected:
            findings.append(
                self.create_finding(
                    title=f"Brute force protection disabled for realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' has brute force protection **disabled**.\n\n"
                        f"**What is Brute Force Protection?**\n"
                        f"Brute force protection detects and blocks repeated failed login attempts, "
                        f"preventing attackers from guessing user passwords through automated trials.\n\n"
                        f"**Security Benefits:**\n"
                        f"1. **Password Guessing Prevention:** Blocks automated password attempts\n"
                        f"2. **Account Lockout:** Temporarily locks accounts after failed attempts\n"
                        f"3. **Attack Detection:** Identifies suspicious login patterns\n"
                        f"4. **Resource Protection:** Prevents DoS through excessive login attempts\n\n"
                        f"**Typical Attack Scenario:**\n"
                        f"- Attacker has list of common passwords (password123, admin, etc.)\n"
                        f"- Attacker tries each password against user accounts\n"
                        f"- Without protection: Attacker can try unlimited passwords\n"
                        f"- With protection: Account locked after N failed attempts\n\n"
                        f"**Why Low Severity?**\n"
                        f"This is defense-in-depth. Strong passwords and MFA are primary defenses, "
                        f"but brute force protection adds an important layer.\n\n"
                        f"**Recommended Settings:**\n"
                        f"- Max Login Failures: 5-10 attempts\n"
                        f"- Wait Time: 15-30 minutes\n"
                        f"- Max Wait: 900 seconds (15 minutes)\n"
                        f"- Failure Reset Time: 12 hours"
                    ),
                    remediation=(
                        f"Enable brute force protection for realm '{realm.realm}':\n\n"
                        f"**Step 1: Enable Protection**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: Security Defenses tab\n"
                        f"4. Click on: Brute Force Detection\n"
                        f"5. Toggle ON: 'Enabled'\n\n"
                        f"**Step 2: Configure Settings (Recommended Values)**\n"
                        f"- **Max Login Failures:** 5-10\n"
                        f"  (Number of failed attempts before lockout)\n"
                        f"- **Wait Increment:** 60 seconds\n"
                        f"  (Additional wait time per failed attempt)\n"
                        f"- **Max Wait:** 900 seconds (15 minutes)\n"
                        f"  (Maximum wait time)\n"
                        f"- **Failure Reset Time:** 12 hours\n"
                        f"  (Time to clear failed attempt counter)\n"
                        f"- **Quick Login Check:** 1000 ms\n"
                        f"  (Minimum time between login attempts)\n\n"
                        f"**Step 3: User Lockout Settings**\n"
                        f"- Enable 'Permanent Lockout' (optional, for high-security)\n"
                        f"- Configure user unlock methods:\n"
                        f"  - Time-based unlock (automatic)\n"
                        f"  - Admin unlock (manual)\n"
                        f"  - Email unlock link (user self-service)\n\n"
                        f"**Step 4: Monitoring**\n"
                        f"1. Go to: Sessions → Login Events\n"
                        f"2. Monitor for 'login_error' events\n"
                        f"3. Review locked accounts regularly\n"
                        f"4. Investigate patterns of failed attempts\n\n"
                        f"**Step 5: User Communication**\n"
                        f"Inform users about account lockout policy:\n"
                        f"- How many attempts allowed\n"
                        f"- How long accounts are locked\n"
                        f"- How to unlock (contact admin, wait, email link)\n\n"
                        f"**Balance Security and Usability:**\n"
                        f"- Too strict: Legitimate users get locked out frequently\n"
                        f"- Too lenient: Attackers have more opportunities\n"
                        f"- Monitor and adjust based on your environment"
                    ),
                    realm=realm,
                    evidence={
                        "realm": realm.realm,
                        "brute_force_protected": False,
                    },
                )
            )

        return findings


@security_check
class ClientSecretsInExportCheck(SecurityCheck):
    """
    Check if client secrets are present in the realm export.

    Client secrets should not be stored in version control or shared via exports.
    """

    check_id = "KC-INFO-001"
    check_name = "Client Secrets in Export"
    category = FindingCategory.MISC
    default_severity = Severity.INFO
    references = [
        "Security Best Practices - Secret Management",
        "OWASP - Sensitive Data Exposure",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Check if client has a secret exposed in configuration
        if client.secret and client.is_confidential:
            findings.append(
                self.create_finding(
                    title=f"Client secret exposed in export for '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has a **client secret present** in the "
                        f"realm export file.\n\n"
                        f"**Security Hygiene Issue:**\n"
                        f"While this is informational (not immediately exploitable), exposing "
                        f"secrets in export files creates security risks:\n\n"
                        f"1. **Version Control:** If exported to git, secret is in repository history\n"
                        f"2. **File Sharing:** Export files may be shared insecurely (email, Slack)\n"
                        f"3. **Backup Storage:** Secrets stored in backups without rotation\n"
                        f"4. **Access Control:** Anyone with read access to export sees secrets\n\n"
                        f"**Best Practices:**\n"
                        f"- Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager)\n"
                        f"- Use environment variables for runtime injection\n"
                        f"- Rotate secrets regularly (quarterly or after exposure)\n"
                        f"- Never commit secrets to version control\n"
                        f"- Use different secrets for dev/staging/production\n\n"
                        f"**This Export:**\n"
                        f"The current export contains the secret for '{client.clientId}'. If this "
                        f"export is used for configuration management or shared, the secret should "
                        f"be removed and managed separately.\n\n"
                        f"**Recommendation:**\n"
                        f"Migrate to asymmetric authentication (private_key_jwt) which doesn't "
                        f"require shared secrets. See check KC-AUTH-002 for details."
                    ),
                    remediation=(
                        f"Remove client secret from export and manage separately:\n\n"
                        f"**Option 1: Remove Secret from Export (Immediate)**\n"
                        f"1. Open realm export file in text editor\n"
                        f"2. Find client '{client.clientId}'\n"
                        f"3. Remove or redact the 'secret' field:\n"
                        f"   ```json\n"
                        f"   {{\n"
                        f'     "clientId": "{client.clientId}",\n'
                        f'     "secret": "**REMOVED**",  // or delete this line\n'
                        f"     ...\n"
                        f"   }}\n"
                        f"   ```\n"
                        f"4. Store actual secret in secure vault\n"
                        f"5. Document secret retrieval process for deployments\n\n"
                        f"**Option 2: Use Environment Variables**\n"
                        f"```bash\n"
                        f"# Store in environment\n"
                        f"export CLIENT_SECRET_{client.clientId.upper().replace('-', '_')}='<secret>'\n\n"
                        f"# Configure Keycloak to read from environment\n"
                        f"# (requires custom configuration or deployment scripts)\n"
                        f"```\n\n"
                        f"**Option 3: Migrate to Asymmetric Auth (Best Long-term)**\n"
                        f"Switch to private_key_jwt authentication:\n"
                        f"- No shared secrets needed\n"
                        f"- Private key stays on client\n"
                        f"- Public key in Keycloak (safe to export)\n"
                        f"- See KC-AUTH-002 remediation for details\n\n"
                        f"**Immediate Actions:**\n"
                        f"1. Rotate this secret if export was shared insecurely\n"
                        f"2. Check if export is in version control (remove from history)\n"
                        f"3. Implement secret management strategy\n"
                        f"4. Document process for handling secrets in exports\n\n"
                        f"**For CI/CD:**\n"
                        f"- Use secret injection at deployment time\n"
                        f"- Never hardcode secrets in pipeline configurations\n"
                        f"- Use provider-specific secret management (GitHub Secrets, GitLab CI/CD Variables)"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "has_secret": True,
                        "secret_length": len(client.secret) if client.secret else 0,
                        "confidential": True,
                    },
                )
            )

        return findings


@security_check
class MissingClientDescriptionCheck(SecurityCheck):
    """
    Check if clients are missing descriptions.

    Descriptions help with documentation and maintenance.
    """

    check_id = "KC-BP-001"
    check_name = "Missing Client Description"
    category = FindingCategory.MISC
    default_severity = Severity.INFO
    references = [
        "Documentation Best Practices",
        "Keycloak Administration Guide",
    ]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Only report for enabled clients without descriptions
        if client.enabled and not client.description:
            findings.append(
                self.create_finding(
                    title=f"Client '{client.clientId}' missing description",
                    description=(
                        f"Client '{client.clientId}' does not have a description field.\n\n"
                        f"**Why Descriptions Matter:**\n\n"
                        f"1. **Documentation:** Helps admins understand client purpose\n"
                        f"2. **Maintenance:** Easier to identify clients during reviews\n"
                        f"3. **Audit Trail:** Documents when and why clients were created\n"
                        f"4. **Team Knowledge:** Reduces dependency on individual knowledge\n"
                        f"5. **Compliance:** Some frameworks require documentation\n\n"
                        f"**Good Description Should Include:**\n"
                        f"- Purpose of the client (e.g., 'Production web application')\n"
                        f"- Application name and environment\n"
                        f"- Team or owner responsible\n"
                        f"- Creation date or ticket reference\n"
                        f"- Any special configuration notes\n\n"
                        f"**Example Descriptions:**\n"
                        f"- 'Production web app - Customer Portal (owned by Platform team)'\n"
                        f"- 'Staging mobile app - iOS (v2.5+)'\n"
                        f"- 'CI/CD service account for automated deployments'\n"
                        f"- 'Legacy integration - scheduled for deprecation Q3 2025'\n\n"
                        f"**This is Informational:**\n"
                        f"Missing descriptions don't create security vulnerabilities, but they "
                        f"make security management harder. Well-documented clients are easier to "
                        f"audit, review, and maintain."
                    ),
                    remediation=(
                        f"Add description to client '{client.clientId}':\n\n"
                        f"**Step 1: Add Description in Keycloak**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. Fill in 'Description' field with meaningful text:\n"
                        f"   Example: '[Environment] [App Name] - [Purpose] (Owner: [Team])'\n"
                        f"5. Click 'Save'\n\n"
                        f"**Step 2: Establish Description Standards**\n"
                        f"Create documentation template for your team:\n"
                        f"```\n"
                        f"Description Format:\n"
                        f"[ENVIRONMENT] [APPLICATION] - [PURPOSE]\n"
                        f"Owner: [TEAM]\n"
                        f"Created: [DATE]\n"
                        f"Notes: [SPECIAL_CONFIG]\n\n"
                        f"Examples:\n"
                        f"- PROD Customer Portal - Public web app | Owner: Platform | Created: 2025-01\n"
                        f"- DEV Mobile App - iOS testing | Owner: Mobile Team | Temp credentials\n"
                        f"```\n\n"
                        f"**Step 3: Document All Existing Clients**\n"
                        f"Review and document all clients in the realm:\n"
                        f"1. List all clients: Get current count ({realm.clients.__len__()} in this realm)\n"
                        f"2. Research purpose if unclear (check with teams)\n"
                        f"3. Add descriptions systematically\n"
                        f"4. Identify and remove unused clients\n\n"
                        f"**Step 4: Make It Policy**\n"
                        f"Require descriptions for new clients:\n"
                        f"- Add to client creation checklist\n"
                        f"- Include in developer documentation\n"
                        f"- Review during security audits\n"
                        f"- Reject PRs/tickets without descriptions"
                    ),
                    realm=realm,
                    client=client,
                    evidence={
                        "client_id": client.clientId,
                        "has_description": False,
                        "has_name": client.name is not None,
                        "enabled": True,
                    },
                )
            )

        return findings


@security_check
class ExcessiveImplicitTokenLifespanCheck(SecurityCheck):
    """
    Check for excessive access token lifespan specifically for implicit flow.

    While implicit flow should be disabled entirely, if it exists, token
    lifespans should be very short.
    """

    check_id = "KC-TOKEN-004"
    check_name = "Excessive Implicit Flow Token Lifespan"
    category = FindingCategory.TOKEN_SECURITY
    default_severity = Severity.MEDIUM
    references = [
        "RFC 9700 - Implicit Flow Deprecated",
        "OAuth 2.0 Security Best Practices",
    ]

    # Implicit flow tokens should be very short (max 15 minutes)
    MAX_IMPLICIT_LIFESPAN = 900

    def check_realm(self, realm: RealmConfig) -> list[Finding]:
        findings = []

        # Check if any client has implicit flow enabled
        has_implicit = any(c.implicitFlowEnabled for c in realm.clients if c.enabled)

        if has_implicit and realm.accessTokenLifespanForImplicitFlow > self.MAX_IMPLICIT_LIFESPAN:
            findings.append(
                self.create_finding(
                    title=f"Excessive implicit flow token lifespan in realm '{realm.realm}'",
                    description=(
                        f"Realm '{realm.realm}' has implicit flow clients and an access token "
                        f"lifespan of **{realm.accessTokenLifespanForImplicitFlow} seconds** "
                        f"({realm.accessTokenLifespanForImplicitFlow // 60} minutes) for implicit flow.\n\n"
                        f"**Context:**\n"
                        f"While implicit flow is **deprecated and should be disabled** (see KC-FLOW-001), "
                        f"if it must remain temporarily during migration, token lifespans should be "
                        f"**very short** to limit exposure risk.\n\n"
                        f"**Why Implicit Flow Tokens Are High-Risk:**\n"
                        f"1. **URL Exposure:** Tokens appear in URL fragments\n"
                        f"2. **Browser History:** Permanent record of tokens\n"
                        f"3. **Referer Leaks:** Sent to third-party sites\n"
                        f"4. **No Refresh:** Can't revoke, must wait for expiry\n\n"
                        f"**Recommended Settings:**\n"
                        f"- **Best:** Disable implicit flow entirely (KC-FLOW-001)\n"
                        f"- **If required temporarily:** Max 15 minutes (900 seconds)\n"
                        f"- **Current:** {realm.accessTokenLifespanForImplicitFlow // 60} minutes "
                        f"(TOO LONG)\n\n"
                        f"**Attack Window:**\n"
                        f"With {realm.accessTokenLifespanForImplicitFlow // 60}-minute tokens, "
                        f"attackers who steal tokens (via URL leak, history access, etc.) have "
                        f"extended time to exploit them."
                    ),
                    remediation=(
                        f"Reduce implicit flow token lifespan for realm '{realm.realm}':\n\n"
                        f"**Priority 1: Disable Implicit Flow (Recommended)**\n"
                        f"See remediation for check KC-FLOW-001.\n"
                        f"Migrate all clients to authorization code + PKCE flow.\n\n"
                        f"**Priority 2: Reduce Token Lifespan (If Migration Delayed)**\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Realm Settings → '{realm.realm}'\n"
                        f"3. Go to: Tokens tab\n"
                        f"4. Find: 'Access Token Lifespan For Implicit Flow'\n"
                        f"5. Set to: **5-15 minutes** (300-900 seconds)\n"
                        f"   - Recommended: 5 minutes (300 seconds)\n"
                        f"   - Maximum: 15 minutes (900 seconds)\n"
                        f"   - Current: {realm.accessTokenLifespanForImplicitFlow} seconds\n"
                        f"6. Click 'Save'\n\n"
                        f"**Client-Side Impact:**\n"
                        f"- Users may need to re-authenticate more frequently\n"
                        f"- Implement silent token renewal if possible\n"
                        f"- Monitor user experience during transition\n\n"
                        f"**Migration Timeline:**\n"
                        f"1. **Immediate:** Reduce token lifespan to 15 min\n"
                        f"2. **Week 1-2:** Begin migrating clients to auth code flow\n"
                        f"3. **Week 3-4:** Complete migration\n"
                        f"4. **Week 5:** Disable implicit flow entirely\n\n"
                        f"**Testing:**\n"
                        f"1. Verify tokens expire at configured time\n"
                        f"2. Test user experience with shorter lifespans\n"
                        f"3. Confirm automatic re-authentication works\n"
                        f"4. Monitor for user complaints or issues"
                    ),
                    realm=realm,
                    evidence={
                        "realm": realm.realm,
                        "implicit_token_lifespan": realm.accessTokenLifespanForImplicitFlow,
                        "implicit_token_lifespan_minutes": realm.accessTokenLifespanForImplicitFlow
                        // 60,
                        "recommended_max": self.MAX_IMPLICIT_LIFESPAN,
                        "has_implicit_clients": has_implicit,
                        "implicit_client_count": sum(
                            1 for c in realm.clients if c.implicitFlowEnabled and c.enabled
                        ),
                    },
                )
            )

        return findings


@security_check
class ServiceAccountsEnabledCheck(SecurityCheck):
    """Check if service accounts are enabled. Review necessity and audit usage."""

    check_id = "KC-MISC-005"
    check_name = "Service Accounts Enabled (Review)"
    category = FindingCategory.MISC
    default_severity = Severity.LOW
    references = ["OAuth 2.0 Client Credentials Grant", "Service Account Best Practices"]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []
        if client.serviceAccountsEnabled:
            findings.append(
                self.create_finding(
                    title=f"Service accounts enabled for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' has service accounts enabled (client credentials grant). "
                        f"While not inherently insecure, ensure this is necessary and properly audited.\n\n"
                        f"**Service Account Usage:**\n"
                        f"- Machine-to-machine authentication\n"
                        f"- Background processes, CI/CD pipelines\n"
                        f"- No user context\n\n"
                        f"**Review Points:**\n"
                        f"- Is service account access still needed?\n"
                        f"- Are service account actions logged?\n"
                        f"- Are credentials stored securely?\n"
                        f"- Is scope limited to minimum required?"
                    ),
                    remediation=(
                        f"Review service account usage for client '{client.clientId}':\n\n"
                        f"1. Verify necessity - disable if not needed\n"
                        f"2. Limit scope to minimum required permissions\n"
                        f"3. Enable audit logging for service account actions\n"
                        f"4. Rotate credentials regularly\n"
                        f"5. Store credentials in secure vault (not source code)"
                    ),
                    realm=realm,
                    client=client,
                    evidence={"client_id": client.clientId, "service_accounts_enabled": True},
                )
            )
        return findings


@security_check
class NoUserConsentRequiredCheck(SecurityCheck):
    """Check if user consent is not required for third-party apps."""

    check_id = "KC-MISC-006"
    check_name = "No User Consent Required"
    category = FindingCategory.MISC
    default_severity = Severity.LOW
    references = ["OpenID Connect Core - Consent", "OAuth 2.0 User Consent Best Practices"]

    def check_client(self, client: ClientConfig, realm: RealmConfig) -> list[Finding]:
        findings = []
        if not client.consentRequired and not client.is_public and client.standardFlowEnabled:
            findings.append(
                self.create_finding(
                    title=f"No user consent required for client '{client.clientId}'",
                    description=(
                        f"Client '{client.clientId}' does not require user consent. "
                        f"For third-party applications, users should explicitly approve access to their data.\n\n"
                        f"**User Consent Benefits:**\n"
                        f"- Users see what permissions are granted\n"
                        f"- Users can decline access\n"
                        f"- Transparency and trust\n"
                        f"- Compliance with privacy regulations (GDPR, CCPA)\n\n"
                        f"**When Consent is Recommended:**\n"
                        f"- Third-party applications\n"
                        f"- Apps accessing sensitive data\n"
                        f"- Compliance requirements\n\n"
                        f"**When Consent May Be Skipped:**\n"
                        f"- First-party applications\n"
                        f"- Single sign-on within organization"
                    ),
                    remediation=(
                        f"Enable user consent for client '{client.clientId}':\n\n"
                        f"1. Log into Keycloak Admin Console\n"
                        f"2. Navigate to: Clients → '{client.clientId}'\n"
                        f"3. Go to: Settings tab\n"
                        f"4. Enable: 'Consent Required'\n"
                        f"5. Define consent text and display name\n"
                        f"6. Click 'Save'\n\n"
                        f"Users will now see a consent screen showing requested permissions."
                    ),
                    realm=realm,
                    client=client,
                    evidence={"client_id": client.clientId, "consent_required": False},
                )
            )
        return findings
