"""Shared test fixtures and configuration.

This module provides shared pytest fixtures and configuration for all test modules.
"""

import os
import pytest
from typing import Generator, Dict, Any
from pathlib import Path
from datetime import datetime
from rich.console import Console
from argparse import Namespace

from vault_cli.storage import PasswordStore
from vault_cli.crypto import CryptoManager

if TYPE_CHECKING:
    from _pytest.fixtures import FixtureRequest
    from _pytest.tmpdir import TempPathFactory
    from pytest_mock.plugin import MockerFixture

@pytest.fixture
def mock_console() -> Console:
    """Create a mock console for testing.

    Returns:
        Console: Mock Rich console with forced terminal mode
    """
    return Console(force_terminal=True)

@pytest.fixture
def temp_key_path(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary directory for key storage.

    Args:
        tmp_path: Pytest temporary path fixture

    Yields:
        Path: Temporary directory path
    """
    key_path = tmp_path / ".password_manager"
    key_path.mkdir(parents=True)
    original_home = os.environ.get('HOME')
    os.environ['HOME'] = str(tmp_path)
    yield key_path
    if original_home:
        os.environ['HOME'] = original_home

@pytest.fixture
def crypto_manager(temp_key_path: Path) -> CryptoManager:
    """Create a CryptoManager instance with temporary key storage.

    Args:
        temp_key_path: Temporary key storage path

    Returns:
        CryptoManager: Initialized crypto manager
    """
    return CryptoManager()

@pytest.fixture
def temp_store_file(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary password store file.

    Args:
        tmp_path: Pytest temporary path fixture

    Yields:
        Path: Temporary storage file path
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

@pytest.fixture
def mock_args() -> Namespace:
    """Create mock command line arguments.

    Returns:
        Namespace: Mock arguments for testing
    """
    args = Namespace()
    args.site = "test.com"
    args.username = "testuser"
    args.url = "https://test.com"
    args.tags = ["test"]
    args.notes = "Test notes"
    return args

def pytest_configure(config):
    """Configure pytest for the test suite.

    Args:
        config: Pytest config object
    """
    # Add custom markers
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running"
    )

def pytest_collection_modifyitems(items):
    """Modify test items in-place to add markers.

    Args:
        items: List of test items
    """
    for item in items:
        # Mark all tests in the integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Mark slow tests
        if "slow" in item.keywords:
            item.add_marker(pytest.mark.slow)