"""Test module for password storage functionality."""

import json
import os
from datetime import datetime
from typing import Dict, Any, Generator
import pytest
from pathlib import Path

from vault_cli.storage import PasswordStore

if TYPE_CHECKING:
    from _pytest.fixtures import FixtureRequest
    from pytest_mock.plugin import MockerFixture

@pytest.fixture
def temp_store_file(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary password store file.

    Args:
        tmp_path: Pytest temporary path fixture

    Yields:
        Path: Path to temporary storage file
    """
    store_file = tmp_path / "test_passwords.json"
    yield store_file
    if store_file.exists():
        store_file.unlink()

@pytest.fixture
def store(temp_store_file: Path) -> PasswordStore:
    """Create a PasswordStore instance with temporary storage.

    Args:
        temp_store_file: Path to temporary storage file

    Returns:
        PasswordStore: Initialized password store
    """
    return PasswordStore(temp_store_file)

@pytest.fixture
def sample_password_data() -> Dict[str, Any]:
    """Create sample password entry data.

    Returns:
        Dict[str, Any]: Sample password entry
    """
    return {
        'username': 'testuser',
        'password': 'encrypted_password',
        'url': 'https://test.com',
        'tags': ['test', 'sample'],
        'notes': 'Test notes',
        'created_at': datetime.now().isoformat(),
        'modified_at': datetime.now().isoformat()
    }

class TestPasswordStore:
    """Test cases for PasswordStore class."""

    def test_init_creates_file(self, temp_store_file: Path) -> None:
        """Test store initialization creates storage file.

        Args:
            temp_store_file: Path to temporary storage file
        """
        PasswordStore(temp_store_file)
        assert temp_store_file.exists()
        with open(temp_store_file) as f:
            data = json.load(f)
            assert 'passwords' in data
            assert 'index_mapping' in data

    def test_add_password(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test adding a new password entry.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        store.add_password(
            site='test.com',
            username=sample_password_data['username'],
            encrypted_password=sample_password_data['password'],
            url=sample_password_data['url'],
            tags=sample_password_data['tags'],
            notes=sample_password_data['notes']
        )

        # Verify password was added
        entry = store.get_password('test.com')
        assert entry is not None
        assert entry['username'] == sample_password_data['username']
        assert entry['password'] == sample_password_data['password']
        assert entry['url'] == sample_password_data['url']
        assert entry['tags'] == sample_password_data['tags']
        assert entry['notes'] == sample_password_data['notes']
        assert 'created_at' in entry
        assert 'modified_at' in entry

    def test_add_duplicate_password(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test adding a duplicate password entry.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        store.add_password('test.com', 'testuser', 'encrypted_password')

        with pytest.raises(ValueError, match="Password entry for test.com already exists"):
            store.add_password('test.com', 'testuser', 'encrypted_password')

    def test_get_password(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test retrieving a password entry.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        # Add a password
        store.add_password('test.com', 'testuser', 'encrypted_password')

        # Test retrieval
        entry = store.get_password('test.com')
        assert entry is not None
        assert entry['username'] == 'testuser'
        assert entry['password'] == 'encrypted_password'

        # Test non-existent entry
        assert store.get_password('nonexistent.com') is None

    def test_list_sites(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test listing all sites.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        # Add multiple passwords
        sites = ['test1.com', 'test2.com', 'test3.com']
        for site in sites:
            store.add_password(site, 'testuser', 'encrypted_password')

        # Test listing
        stored_sites = store.list_sites()
        assert len(stored_sites) == len(sites)
        assert all(site in stored_sites for site in sites)

    def test_search_by_tags(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test searching passwords by tags.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        # Add passwords with different tags
        store.add_password('work.com', 'user1', 'pass1', tags=['work'])
        store.add_password('personal.com', 'user2', 'pass2', tags=['personal'])
        store.add_password('both.com', 'user3', 'pass3', tags=['work', 'personal'])

        # Test tag search
        work_sites = store.search_by_tags(['work'])
        assert len(work_sites) == 2
        assert 'work.com' in work_sites
        assert 'both.com' in work_sites

        personal_sites = store.search_by_tags(['personal'])
        assert len(personal_sites) == 2
        assert 'personal.com' in personal_sites
        assert 'both.com' in personal_sites

    def test_update_password(
        self,
        store: PasswordStore,
        sample_password_data: Dict[str, Any]
    ) -> None:
        """Test updating a password entry.

        Args:
            store: Initialized password store
            sample_password_data: Sample password entry data
        """
        # Add initial password
        store.add_password('test.com', 'testuser', 'old_password')
        initial_modified = store.get_password('test.com')['modified_at']

        # Update password
        store.update_password(
            'test.com',
            encrypted_password='new_password',
            url='https://new.test.com',
            tags=['updated'],
            notes='Updated notes'
        )

        # Verify updates
        entry = store.get_password('test.com')
        assert entry['password'] == 'new_password'
        assert entry['url'] == 'https://new.test.com'
        assert entry['tags'] == ['updated']
        assert entry['notes'] == 'Updated notes'
        assert entry['modified_at'] > initial_modified

    def test_delete_password(self, store: PasswordStore) -> None:
        """Test deleting a password entry.

        Args:
            store: Initialized password store
        """
        # Add password
        store.add_password('test.com', 'testuser', 'encrypted_password')
        assert store.get_password('test.com') is not None

        # Delete password
        store.delete_password('test.com')
        assert store.get_password('test.com') is None

        # Test deleting non-existent entry
        with pytest.raises(KeyError):
            store.delete_password('nonexistent.com')

    def test_index_mapping(self, store: PasswordStore) -> None:
        """Test index mapping functionality.

        Args:
            store: Initialized password store
        """
        # Add mappings
        store.add_index_mapping('1', 'test1.com')
        store.add_index_mapping('2', 'test2.com')

        # Test retrieval
        assert store.get_site_by_index('1') == 'test1.com'
        assert store.get_site_by_index('2') == 'test2.com'
        assert store.get_site_by_index('3') is None

        # Test clearing
        store.clear_index_mapping()
        assert store.get_site_by_index('1') is None