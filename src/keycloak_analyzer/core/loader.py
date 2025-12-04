"""Realm configuration loader."""

import json
import logging
from pathlib import Path
from typing import Any, Union

from pydantic import ValidationError

from ..models import RealmConfig

logger = logging.getLogger(__name__)


class RealmLoadError(Exception):
    """Exception raised when realm loading fails."""

    pass


class RealmLoader:
    """Loads and parses Keycloak realm export files."""

    def load(self, file_path: Path) -> list[RealmConfig]:
        """
        Load realm configuration(s) from a JSON file.

        Supports both single-realm and multi-realm export formats:
        - Single realm: {"id": "...", "realm": "...", "clients": [...]}
        - Multi-realm: [{"id": "...", "realm": "..."}, ...]

        Args:
            file_path: Path to the realm export JSON file.

        Returns:
            List of RealmConfig objects (one or more realms).

        Raises:
            RealmLoadError: If file cannot be read or parsed.
        """
        logger.info(f"Loading realm configuration from: {file_path}")

        try:
            # Read the JSON file
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

        except FileNotFoundError:
            raise RealmLoadError(f"File not found: {file_path}")
        except json.JSONDecodeError as e:
            raise RealmLoadError(f"Invalid JSON in {file_path}: {e}")
        except Exception as e:
            raise RealmLoadError(f"Error reading {file_path}: {e}")

        # Parse the data
        try:
            realms = self._parse_realm_data(data, file_path)
        except Exception as e:
            raise RealmLoadError(f"Error parsing realm data from {file_path}: {e}")

        logger.info(f"Successfully loaded {len(realms)} realm(s) from {file_path}")

        return realms

    def _parse_realm_data(
        self, data: Union[dict[str, Any], list[dict[str, Any]]], file_path: Path
    ) -> list[RealmConfig]:
        """
        Parse JSON data into RealmConfig objects.

        Args:
            data: JSON data (dict for single realm, list for multi-realm).
            file_path: Original file path (for metadata).

        Returns:
            List of RealmConfig objects.

        Raises:
            ValidationError: If Pydantic validation fails.
            ValueError: If data format is invalid.
        """
        realms: list[RealmConfig] = []

        # Determine if it's single-realm or multi-realm format
        if isinstance(data, dict):
            # Single realm export
            realm = self._create_realm_config(data, file_path)
            realms.append(realm)

        elif isinstance(data, list):
            # Multi-realm export
            if not data:
                raise ValueError("Empty realm list in JSON file")

            for idx, realm_data in enumerate(data):
                if not isinstance(realm_data, dict):
                    logger.warning(f"Skipping invalid realm entry at index {idx} in {file_path}")
                    continue

                try:
                    realm = self._create_realm_config(realm_data, file_path)
                    realms.append(realm)
                except ValidationError as e:
                    logger.warning(
                        f"Validation failed for realm at index {idx} in {file_path}: {e}"
                    )
                    continue

        else:
            raise ValueError(
                f"Invalid realm export format: expected dict or list, got {type(data)}"
            )

        if not realms:
            raise ValueError(f"No valid realms found in {file_path}")

        return realms

    def _create_realm_config(self, data: dict[str, Any], file_path: Path) -> RealmConfig:
        """
        Create a RealmConfig from dictionary data.

        Args:
            data: Realm configuration dictionary.
            file_path: Original file path (for metadata).

        Returns:
            RealmConfig object with metadata attached.

        Raises:
            ValidationError: If Pydantic validation fails.
        """
        # Parse with Pydantic (validates structure and types)
        realm = RealmConfig(**data)

        # Attach file metadata
        realm.file_path = str(file_path)
        realm.file_size = file_path.stat().st_size if file_path.exists() else None

        logger.debug(f"Loaded realm '{realm.realm}' with {len(realm.clients)} client(s)")

        return realm

    def load_multiple(self, file_paths: list[Path]) -> list[RealmConfig]:
        """
        Load realm configurations from multiple files.

        Args:
            file_paths: List of paths to realm export files.

        Returns:
            Flat list of all RealmConfig objects from all files.

        Note:
            Files that fail to load are logged but don't stop processing.
        """
        all_realms: list[RealmConfig] = []

        for file_path in file_paths:
            try:
                realms = self.load(file_path)
                all_realms.extend(realms)
            except RealmLoadError as e:
                logger.error(f"Failed to load {file_path}: {e}")
                continue

        logger.info(f"Loaded {len(all_realms)} realm(s) from {len(file_paths)} file(s)")

        return all_realms

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return "RealmLoader()"
