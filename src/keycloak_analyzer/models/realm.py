"""Keycloak realm configuration models."""

from typing import Any, Optional

from pydantic import BaseModel, Field

from .client import ClientConfig


class RealmConfig(BaseModel):
    """Top-level Keycloak realm configuration."""

    # Identity
    id: str
    realm: str
    displayName: Optional[str] = None
    enabled: bool = True

    # Security settings
    sslRequired: str = "external"  # "all", "external", "none"
    bruteForceProtected: bool = False

    # Token lifespans (seconds)
    accessTokenLifespan: int = 300  # 5 minutes default
    accessTokenLifespanForImplicitFlow: int = 900  # 15 minutes default
    ssoSessionIdleTimeout: int = 1800  # 30 minutes default
    ssoSessionMaxLifespan: int = 36000  # 10 hours default
    offlineSessionIdleTimeout: int = 2592000  # 30 days default
    refreshTokenMaxReuse: int = 0  # 0 = no reuse allowed (rotation)

    # Client configurations
    clients: list[ClientConfig] = Field(default_factory=list)

    # Authentication flows
    authenticationFlows: Optional[list[dict[str, Any]]] = None

    # Identity providers
    identityProviders: Optional[list[dict[str, Any]]] = None

    # Custom attributes
    attributes: dict[str, str] = Field(default_factory=dict)

    # Realm-level roles
    roles: Optional[dict[str, Any]] = None

    # File metadata (not from JSON, added during loading)
    file_path: Optional[str] = Field(None, exclude=True)
    file_size: Optional[int] = Field(None, exclude=True)

    class Config:
        # Allow extra fields for forward compatibility with newer Keycloak versions
        extra = "allow"

    # Computed properties for security analysis

    @property
    def ssl_enforced(self) -> bool:
        """Check if SSL is required for all connections."""
        return self.sslRequired == "all"

    @property
    def ssl_disabled(self) -> bool:
        """Check if SSL is completely disabled."""
        return self.sslRequired == "none"

    @property
    def refresh_token_rotation_enabled(self) -> bool:
        """Check if refresh token rotation is enabled."""
        return self.refreshTokenMaxReuse == 0

    @property
    def public_clients(self) -> list[ClientConfig]:
        """Get all public clients in this realm."""
        return [c for c in self.clients if c.is_public]

    @property
    def confidential_clients(self) -> list[ClientConfig]:
        """Get all confidential clients in this realm."""
        return [c for c in self.clients if c.is_confidential]

    @property
    def clients_with_deprecated_flows(self) -> list[ClientConfig]:
        """Get all clients using deprecated OAuth flows."""
        return [c for c in self.clients if c.uses_deprecated_flows]

    @property
    def enabled_clients(self) -> list[ClientConfig]:
        """Get all enabled clients."""
        return [c for c in self.clients if c.enabled]

    def get_client_by_id(self, client_id: str) -> Optional[ClientConfig]:
        """
        Get a client by its client ID.

        Args:
            client_id: The client ID to search for.

        Returns:
            ClientConfig if found, None otherwise.
        """
        for client in self.clients:
            if client.clientId == client_id:
                return client
        return None

    def __str__(self) -> str:
        """Human-readable string representation."""
        return (
            f"Realm('{self.realm}', "
            f"clients={len(self.clients)}, "
            f"enabled={self.enabled})"
        )

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"RealmConfig(realm='{self.realm}', "
            f"id='{self.id}', "
            f"clients={len(self.clients)}, "
            f"sslRequired='{self.sslRequired}')"
        )
