"""Password storage and management module.

This module provides functionality for:
- Secure storage of encrypted passwords
- Password entry management (add/update/delete)
- Password retrieval and listing
- Tag-based organization
- Index-based access
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

class PasswordStore:
    """Manages the storage and retrieval of password entries."""

    def __init__(self, file_path: Union[str, Path]) -> None:
        """Initialize the password store.

        Args:
            file_path: Path to the password storage file

        Raises:
            OSError: If the storage file cannot be accessed
        """
        self.file_path = Path(file_path)
        self.passwords: Dict[str, Dict[str, Any]] = {}
        self.index_mapping: Dict[str, str] = {}
        self._load_passwords()

    def _load_passwords(self) -> None:
        """Load passwords from storage file.

        Creates an empty storage file if it doesn't exist.
        """
        try:
            if self.file_path.exists():
                with open(self.file_path, 'r') as f:
                    data = json.load(f)
                    self.passwords = data.get('passwords', {})
                    self.index_mapping = data.get('index_mapping', {})
            else:
                self._save_passwords()
        except Exception as e:
            raise OSError(f"Failed to load passwords: {str(e)}")

    def _save_passwords(self) -> None:
        """Save passwords to storage file.

        Raises:
            OSError: If writing to storage file fails
        """
        try:
            with open(self.file_path, 'w') as f:
                json.dump({
                    'passwords': self.passwords,
                    'index_mapping': self.index_mapping
                }, f, indent=4)
        except Exception as e:
            raise OSError(f"Failed to save passwords: {str(e)}")

    def add_password(
        self,
        site: str,
        username: str,
        encrypted_password: str,
        url: Optional[str] = None,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None
    ) -> None:
        """Add a new password entry.

        Args:
            site: Website or application name
            username: Account username
            encrypted_password: Encrypted password string
            url: Optional website URL
            tags: Optional list of tags for organization
            notes: Optional additional notes

        Raises:
            ValueError: If site already exists
        """
        if site in self.passwords:
            raise ValueError(f"Password entry for {site} already exists")

        current_time = datetime.now().isoformat()
        self.passwords[site] = {
            'username': username,
            'password': encrypted_password,
            'url': url or '',
            'tags': tags or [],
            'notes': notes or '',
            'created_at': current_time,
            'modified_at': current_time
        }
        self._save_passwords()

    def get_password(self, site: str) -> Optional[Dict[str, Any]]:
        """Retrieve a password entry.

        Args:
            site: Website or application name

        Returns:
            Optional[Dict[str, Any]]: Password entry if found, None otherwise
        """
        return self.passwords.get(site)

    def list_sites(self) -> List[str]:
        """List all stored sites.

        Returns:
            List[str]: List of all site names
        """
        return list(self.passwords.keys())

    def search_by_tags(self, tags: List[str]) -> List[str]:
        """Search password entries by tags.

        Args:
            tags: List of tags to search for

        Returns:
            List[str]: List of sites matching any of the tags
        """
        if not tags:
            return self.list_sites()

        matching_sites = []
        for site, data in self.passwords.items():
            if any(tag in data.get('tags', []) for tag in tags):
                matching_sites.append(site)
        return matching_sites

    def update_password(
        self,
        site: str,
        encrypted_password: Optional[str] = None,
        url: Optional[str] = None,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None
    ) -> None:
        """Update an existing password entry.

        Args:
            site: Website or application name
            encrypted_password: Optional new encrypted password
            url: Optional new URL
            tags: Optional new tags list
            notes: Optional new notes

        Raises:
            KeyError: If site doesn't exist
        """
        if site not in self.passwords:
            raise KeyError(f"No password entry found for {site}")

        if encrypted_password:
            self.passwords[site]['password'] = encrypted_password
        if url is not None:
            self.passwords[site]['url'] = url
        if tags is not None:
            self.passwords[site]['tags'] = tags
        if notes is not None:
            self.passwords[site]['notes'] = notes

        self.passwords[site]['modified_at'] = datetime.now().isoformat()
        self._save_passwords()

    def delete_password(self, site: str) -> None:
        """Delete a password entry.

        Args:
            site: Website or application name

        Raises:
            KeyError: If site doesn't exist
        """
        if site not in self.passwords:
            raise KeyError(f"No password entry found for {site}")

        del self.passwords[site]
        self._save_passwords()

    def clear_index_mapping(self) -> None:
        """Clear the index to site mapping."""
        self.index_mapping.clear()

    def add_index_mapping(self, index: str, site: str) -> None:
        """Add an index to site mapping.

        Args:
            index: Index number as string
            site: Website or application name
        """
        self.index_mapping[index] = site

    def get_site_by_index(self, index: str) -> Optional[str]:
        """Get site name by index.

        Args:
            index: Index number as string

        Returns:
            Optional[str]: Site name if found, None otherwise
        """
        return self.index_mapping.get(index)