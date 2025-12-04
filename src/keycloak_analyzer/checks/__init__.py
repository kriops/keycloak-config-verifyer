"""Security checks for Keycloak configurations."""

# Import all check modules to register them
# ruff: noqa: F401 - These imports are used for side effects (registering checks)
from . import client_auth, flows, misc, pkce, redirect_uri, token_security, transport
from .base import CheckRegistry, SecurityCheck, security_check

__all__ = [
    "SecurityCheck",
    "CheckRegistry",
    "security_check",
]
