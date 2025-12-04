"""Tests for redirect URI validation checks."""

import pytest
from src.keycloak_analyzer.checks.redirect_uri import PathTraversalRedirectURICheck
from src.keycloak_analyzer.models import ClientConfig, RealmConfig


@pytest.fixture
def realm():
    """Create a test realm."""
    return RealmConfig(
        realm="test-realm",
        id="test-realm-id",
        enabled=True,
        clients=[],
    )


def test_path_traversal_no_false_positives_for_https(realm):
    """Verify that legitimate HTTPS URLs do not trigger false positives."""
    check = PathTraversalRedirectURICheck()

    # Test with legitimate HTTPS URLs that should NOT be flagged
    legitimate_uris = [
        "https://admin-dev.k8s.met.no/admin/oidc/callback",
        "https://example.com/callback",
        "https://app.example.com/auth/callback",
        "https://staging.example.com/oauth/callback",
        "https://sub.domain.example.com/path/to/callback",
        "http://localhost:3000/callback",
        "http://127.0.0.1:8080/callback",
    ]

    client = ClientConfig(
        clientId="test-client",
        redirectUris=legitimate_uris,
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    # Should have NO findings for legitimate URLs
    assert len(findings) == 0, f"Expected no findings, but got {len(findings)}: {[f.title for f in findings]}"


def test_path_traversal_detects_protocol_relative_urls(realm):
    """Verify that protocol-relative URLs are detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=["//attacker.com/callback"],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"
    assert "//attacker.com/callback" in findings[0].description


def test_path_traversal_detects_parent_directory_traversal(realm):
    """Verify that parent directory traversal patterns are detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=[
            "https://good.com/../attacker.com",
            "https://example.com/path/../../../etc/passwd",
        ],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_detects_url_encoding(realm):
    """Verify that URL-encoded path traversal is detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=[
            "https://good.com/%2e%2e/attacker.com",
            "https://example.com/path%2f..%2fattacker.com",
        ],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_detects_at_symbol_confusion(realm):
    """Verify that @ symbol parser confusion is detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=["https://good.com@attacker.com/callback"],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_detects_relative_paths(realm):
    """Verify that relative path patterns are detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=[
            "https://example.com/./callback",
            "https://example.com/.//callback",
        ],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_detects_backslash(realm):
    """Verify that backslash patterns are detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=["https://example.com\\attacker.com"],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_detects_null_byte(realm):
    """Verify that null byte injection is detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=["https://example.com/callback%00.attacker.com"],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_checks_query_params(realm):
    """Verify that dangerous patterns in query parameters are detected."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=["https://example.com/callback?redirect=../attacker.com"],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 1
    assert findings[0].check_id == "KC-REDIR-004"


def test_path_traversal_handles_empty_redirect_uris(realm):
    """Verify that empty redirect URI list doesn't cause errors."""
    check = PathTraversalRedirectURICheck()

    client = ClientConfig(
        clientId="test-client",
        redirectUris=[],
        publicClient=True,
    )

    findings = check.check_client(client, realm)

    assert len(findings) == 0
