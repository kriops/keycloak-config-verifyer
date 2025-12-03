"""Security checks for Keycloak configurations."""

# Import all check modules to register them
from . import pkce
from . import flows
from . import redirect_uri
from . import transport
from . import token_security
from . import client_auth
from . import misc

from .base import SecurityCheck, CheckRegistry, security_check

__all__ = [
    "SecurityCheck",
    "CheckRegistry",
    "security_check",
]
