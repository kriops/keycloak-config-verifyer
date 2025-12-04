"""Utility functions for grouping findings."""

from collections import defaultdict

from ..models import Finding, Severity


def group_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    """
    Group findings by severity level.

    Args:
        findings: List of findings to group.

    Returns:
        Dictionary mapping severity to list of findings.
    """
    grouped: defaultdict[Severity, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.severity].append(finding)
    return dict(grouped)


def group_by_realm(findings: list[Finding]) -> dict[str, list[Finding]]:
    """
    Group findings by realm name.

    Args:
        findings: List of findings to group.

    Returns:
        Dictionary mapping realm name to list of findings, sorted by realm name.
    """
    grouped: defaultdict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.realm_name].append(finding)
    return dict(sorted(grouped.items()))


def group_by_client(findings: list[Finding]) -> dict[str, dict[str, list[Finding]]]:
    """
    Group findings hierarchically by realm, then by client.
    Filters out realm-level findings (where client_id is None).

    Args:
        findings: List of findings to group.

    Returns:
        Nested dictionary: {realm_name: {client_id: [findings]}}, sorted by realm and client.
    """
    # Filter out realm-level findings first
    client_findings = [f for f in findings if f.client_id is not None]

    # Group by realm, then by client
    realm_groups: defaultdict[str, defaultdict[str, list[Finding]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for finding in client_findings:
        realm_groups[finding.realm_name][finding.client_id].append(finding)

    # Sort and convert to regular dicts
    result = {}
    for realm_name in sorted(realm_groups.keys()):
        result[realm_name] = dict(sorted(realm_groups[realm_name].items()))

    return result


def filter_client_level_findings(findings: list[Finding]) -> list[Finding]:
    """
    Filter to only client-level findings (exclude realm-level findings).

    Args:
        findings: List of findings to filter.

    Returns:
        List of findings where client_id is not None.
    """
    return [f for f in findings if f.client_id is not None]


def count_findings_in_nested_groups(groups: dict[str, dict[str, list[Finding]]]) -> int:
    """
    Count total findings in a nested group structure.

    Args:
        groups: Nested dictionary from group_by_client().

    Returns:
        Total number of findings.
    """
    total = 0
    for realm_clients in groups.values():
        for client_findings in realm_clients.values():
            total += len(client_findings)
    return total
