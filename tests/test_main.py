"""Test module for the main CLI functionality."""

from typing import Any, Dict, List, Optional
import pytest
from unittest.mock import MagicMock, patch
from argparse import Namespace
from rich.console import Console

from vault_cli.main import (
    custom_confirm,
    get_password,
    add_password,
    list_passwords,
    get_password_entry,
    generate_keys,
    main
)

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture
    from _pytest.fixtures import FixtureRequest
    from _pytest.logging import LogCaptureFixture
    from _pytest.monkeypatch import MonkeyPatch
    from pytest_mock.plugin import MockerFixture

@pytest.fixture
def mock_args() -> Namespace:
    """Create mock command line arguments.

    Returns:
        Namespace: Mock arguments for testing
    """
    args = MagicMock()
    args.site = "test.com"
    args.username = "testuser"
    args.url = "https://test.com"
    args.tags = ["test"]
    args.notes = "Test notes"
    return args

@pytest.fixture
def mock_console() -> Console:
    """Create a mock console for testing.

    Returns:
        Console: Mock Rich console
    """
    return Console(force_terminal=True)

class TestMainFunctions:
    """Test cases for main module functions."""

    def test_custom_confirm(self, monkeypatch: MonkeyPatch) -> None:
        """Test custom confirmation prompt.

        Args:
            monkeypatch: Pytest monkeypatch fixture
        """
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        assert custom_confirm("Test?") is True

        monkeypatch.setattr('builtins.input', lambda _: 'n')
        assert custom_confirm("Test?") is False

    @patch('vault_cli.main.PasswordValidator')
    def test_get_password_generation(
        self,
        mock_validator: MagicMock,
        monkeypatch: MonkeyPatch
    ) -> None:
        """Test password generation functionality.

        Args:
            mock_validator: Mock password validator
            monkeypatch: Pytest monkeypatch fixture
        """
        mock_validator.return_value.validate_password.return_value = (True, [])
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        
        password, success = get_password()
        assert success is True
        assert len(password) >= 12
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)

    @patch('vault_cli.main.CryptoManager')
    @patch('vault_cli.main.PasswordStore')
    def test_add_password(
        self,
        mock_store: MagicMock,
        mock_crypto: MagicMock,
        mock_args: Namespace
    ) -> None:
        """Test adding a new password entry.

        Args:
            mock_store: Mock password store
            mock_crypto: Mock crypto manager
            mock_args: Mock command line arguments
        """
        mock_crypto.return_value.encrypt_password.return_value = "encrypted"
        mock_store_instance = mock_store.return_value

        with patch('vault_cli.main.get_password') as mock_get_password:
            mock_get_password.return_value = ("TestPass123!", True)
            add_password(mock_args)

        mock_store_instance.add_password.assert_called_once_with(
            site="test.com",
            username="testuser",
            encrypted_password="encrypted",
            url="https://test.com",
            tags=["test"],
            notes="Test notes"
        )

    @patch('vault_cli.main.PasswordStore')
    def test_list_passwords(
        self,
        mock_store: MagicMock,
        mock_args: Namespace,
        capsys: CaptureFixture[str]
    ) -> None:
        """Test listing password entries.

        Args:
            mock_store: Mock password store
            mock_args: Mock command line arguments
            capsys: Pytest capture fixture
        """
        mock_store_instance = mock_store.return_value
        mock_store_instance.list_sites.return_value = ["test.com"]
        mock_store_instance.get_password.return_value = {
            "username": "testuser",
            "url": "https://test.com",
            "tags": ["test"],
            "modified_at": "2024-03-15T10:30:45.123456"
        }

        list_passwords(mock_args)
        captured = capsys.readouterr()
        assert "test.com" in captured.out
        assert "testuser" in captured.out

    @patch('vault_cli.main.CryptoManager')
    @patch('vault_cli.main.PasswordStore')
    def test_get_password_entry(
        self,
        mock_store: MagicMock,
        mock_crypto: MagicMock,
        mock_args: Namespace,
        capsys: CaptureFixture[str]
    ) -> None:
        """Test retrieving a specific password entry.

        Args:
            mock_store: Mock password store
            mock_crypto: Mock crypto manager
            mock_args: Mock command line arguments
            capsys: Pytest capture fixture
        """
        mock_store_instance = mock_store.return_value
        mock_store_instance.get_password.return_value = {
            "username": "testuser",
            "password": "encrypted",
            "url": "https://test.com",
            "tags": ["test"],
            "notes": "Test notes",
            "modified_at": "2024-03-15T10:30:45.123456"
        }
        mock_crypto.return_value.decrypt_password.return_value = "TestPass123!"

        with patch('vault_cli.main.custom_confirm', return_value=True):
            get_password_entry(mock_args)

        captured = capsys.readouterr()
        assert "test.com" in captured.out
        assert "testuser" in captured.out
        assert "TestPass123!" in captured.out

    def test_main_help(self, capsys: CaptureFixture[str]) -> None:
        """Test main function help output.

        Args:
            capsys: Pytest capture fixture
        """
        with pytest.raises(SystemExit):
            main(["-h"])
        
        captured = capsys.readouterr()
        assert "Secure Password Manager" in captured.out
        assert "Available commands" in captured.out