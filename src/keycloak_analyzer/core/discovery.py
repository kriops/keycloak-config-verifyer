"""File discovery for Keycloak realm exports."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class RealmDiscovery:
    """Discovers Keycloak realm export files in directory trees."""

    # File patterns to match
    REALM_PATTERNS = [
        "*-realm.json",
        "realm-export.json",
    ]

    # Directories to skip during traversal
    SKIP_DIRS = {
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "htmlcov",
    }

    def discover(self, root_path: Path) -> list[Path]:
        """
        Recursively discover Keycloak realm export files.

        Args:
            root_path: Root directory to start scanning from.

        Returns:
            List of absolute paths to discovered realm export files.

        Raises:
            ValueError: If root_path doesn't exist or isn't a directory.
        """
        if not root_path.exists():
            raise ValueError(f"Path does not exist: {root_path}")

        if not root_path.is_dir():
            raise ValueError(f"Path is not a directory: {root_path}")

        discovered_files: list[Path] = []

        logger.info(f"Starting realm file discovery in: {root_path}")

        # Walk the directory tree
        for item in root_path.rglob("*"):
            # Skip if it's in a directory we want to ignore
            if any(skip_dir in item.parts for skip_dir in self.SKIP_DIRS):
                continue

            # Check if it matches any of our patterns
            if item.is_file() and self._matches_pattern(item):
                discovered_files.append(item.absolute())
                logger.debug(f"Discovered realm file: {item}")

        logger.info(f"Discovery complete. Found {len(discovered_files)} realm file(s)")

        # Sort for consistent ordering
        return sorted(discovered_files)

    def _matches_pattern(self, file_path: Path) -> bool:
        """
        Check if a file matches any of the realm export patterns.

        Args:
            file_path: Path to check.

        Returns:
            True if the file matches a pattern, False otherwise.
        """
        file_name = file_path.name

        for pattern in self.REALM_PATTERNS:
            # Simple pattern matching
            if pattern == file_name:
                return True

            # Handle wildcard patterns like "*-realm.json"
            if "*" in pattern:
                suffix = pattern.replace("*", "")
                if file_name.endswith(suffix):
                    return True

        return False

    def discover_single(self, file_path: Path) -> list[Path]:
        """
        Validate and return a single realm export file.

        Useful when the user provides a direct path to a file.

        Args:
            file_path: Path to a single realm export file.

        Returns:
            List containing the single file path (for API consistency).

        Raises:
            ValueError: If file doesn't exist or doesn't match pattern.
        """
        if not file_path.exists():
            raise ValueError(f"File does not exist: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        if not self._matches_pattern(file_path):
            logger.warning(
                f"File '{file_path}' doesn't match realm export patterns, "
                f"but will be processed anyway"
            )

        return [file_path.absolute()]

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"RealmDiscovery(patterns={self.REALM_PATTERNS}, " f"skip_dirs={len(self.SKIP_DIRS)})"
        )
