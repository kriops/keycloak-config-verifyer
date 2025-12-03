"""Keycloak client configuration models."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class ClientConfig(BaseModel):
    """Keycloak OAuth/OIDC client configuration."""

    # Identity
    id: Optional[str] = None  # Internal Keycloak ID
    clientId: str  # Public client identifier
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True

    # Client type
    publicClient: bool = False  # True = public, False = confidential
    bearerOnly: bool = False  # True = resource server only

    # Protocol
    protocol: str = "openid-connect"  # or "saml"

    # OAuth flows
    standardFlowEnabled: bool = True  # Authorization code flow
    implicitFlowEnabled: bool = False  # Implicit flow (DEPRECATED)
    directAccessGrantsEnabled: bool = False  # Password grant (DEPRECATED)
    serviceAccountsEnabled: bool = False  # Client credentials

    # URIs
    rootUrl: Optional[str] = None
    baseUrl: Optional[str] = None
    redirectUris: List[str] = Field(default_factory=list)
    webOrigins: List[str] = Field(default_factory=list)
    adminUrl: Optional[str] = None

    # Authentication
    clientAuthenticatorType: Optional[str] = None
    # Values: "client-secret", "client-jwt", "client-x509"
    secret: Optional[str] = None  # Client secret (confidential clients)

    # Attributes (contains PKCE, token binding, etc.)
    attributes: Dict[str, str] = Field(default_factory=dict)

    # Token settings
    fullScopeAllowed: bool = True  # All scopes vs. specific scopes

    # Protocol mappers
    protocolMappers: Optional[List[Dict[str, Any]]] = None

    # Consent settings
    consentRequired: bool = False

    class Config:
        extra = "allow"  # Allow extra fields for forward compatibility

    # Computed properties for security analysis

    @property
    def pkce_enabled(self) -> bool:
        """Check if PKCE is enforced with S256 method."""
        return self.attributes.get("pkce.code.challenge.method") == "S256"

    @property
    def pkce_method(self) -> Optional[str]:
        """Get PKCE challenge method (S256, plain, or None)."""
        return self.attributes.get("pkce.code.challenge.method")

    @property
    def is_confidential(self) -> bool:
        """Check if client is confidential (not public, not bearer-only)."""
        return not self.publicClient and not self.bearerOnly

    @property
    def is_public(self) -> bool:
        """Check if client is public."""
        return self.publicClient

    @property
    def has_wildcard_redirect(self) -> bool:
        """Check if any redirect URI uses wildcards."""
        for uri in self.redirectUris:
            if '*' in uri or uri == '' or '+' in uri:
                return True
        return False

    @property
    def has_http_redirect(self) -> bool:
        """
        Check if any redirect URI uses HTTP (excluding localhost).

        Returns:
            True if non-localhost HTTP redirect URIs exist.
        """
        for uri in self.redirectUris:
            if uri.startswith('http://'):
                # Allow localhost for native apps
                if not ('localhost' in uri or '127.0.0.1' in uri):
                    return True
        return False

    @property
    def has_wildcard_web_origin(self) -> bool:
        """Check if any web origin uses wildcards."""
        for origin in self.webOrigins:
            if '*' in origin or origin == '+':
                return True
        return False

    @property
    def uses_deprecated_flows(self) -> List[str]:
        """
        Return list of deprecated flows in use.

        Returns:
            List of flow names (e.g., ["implicit", "password"]).
        """
        deprecated = []
        if self.implicitFlowEnabled:
            deprecated.append("implicit")
        if self.directAccessGrantsEnabled:
            deprecated.append("password")
        return deprecated

    @property
    def has_client_authentication(self) -> bool:
        """Check if client has any authentication configured."""
        return bool(self.clientAuthenticatorType) or bool(self.secret)

    @property
    def uses_symmetric_auth(self) -> bool:
        """Check if using symmetric authentication (client secret)."""
        return self.clientAuthenticatorType == "client-secret" or (
            self.secret is not None and not self.clientAuthenticatorType
        )

    @property
    def uses_asymmetric_auth(self) -> bool:
        """Check if using asymmetric authentication (JWT or mTLS)."""
        if not self.clientAuthenticatorType:
            return False
        return self.clientAuthenticatorType in ["client-jwt", "client-x509"]

    def __str__(self) -> str:
        """Human-readable string representation."""
        client_type = "public" if self.publicClient else "confidential"
        return f"Client('{self.clientId}', type={client_type}, enabled={self.enabled})"

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"ClientConfig(clientId='{self.clientId}', "
            f"publicClient={self.publicClient}, "
            f"protocol='{self.protocol}')"
        )
