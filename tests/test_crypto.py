"""Test module for cryptographic operations."""

import os
import base64
from typing import Tuple, Generator, Any
import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey
)

from vault_cli.crypto import CryptoManager

if TYPE_CHECKING:
    from _pytest.fixtures import FixtureRequest
    from _pytest.tmpdir import TempPathFactory
    from pytest_mock.plugin import MockerFixture

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

class TestCryptoManager:
    """Test cases for CryptoManager class."""

    def test_init_creates_key_directory(self, temp_key_path: Path) -> None:
        """Test that initialization creates key directory.

        Args:
            temp_key_path: Temporary key storage path
        """
        CryptoManager()
        assert temp_key_path.exists()
        assert temp_key_path.is_dir()

    def test_key_generation(self, crypto_manager: CryptoManager) -> None:
        """Test RSA key pair generation.

        Args:
            crypto_manager: Initialized crypto manager
        """
        private_key = crypto_manager.private_key
        public_key = crypto_manager.public_key

        assert isinstance(private_key, RSAPrivateKey)
        assert isinstance(public_key, RSAPublicKey)
        assert private_key.key_size == 2048

    def test_key_file_permissions(self, crypto_manager: CryptoManager) -> None:
        """Test key file permissions on Unix-like systems.

        Args:
            crypto_manager: Initialized crypto manager
        """
        if os.name != 'nt':  # Skip on Windows
            private_key_perms = oct(os.stat(crypto_manager.private_key_path).st_mode)[-3:]
            public_key_perms = oct(os.stat(crypto_manager.public_key_path).st_mode)[-3:]
            dir_perms = oct(os.stat(crypto_manager.key_path).st_mode)[-3:]

            assert private_key_perms == '600'
            assert public_key_perms == '644'
            assert dir_perms == '700'

    def test_encryption_decryption(self, crypto_manager: CryptoManager) -> None:
        """Test password encryption and decryption.

        Args:
            crypto_manager: Initialized crypto manager
        """
        test_password = "MySecurePassword123!"
        
        # Test encryption
        encrypted = crypto_manager.encrypt_password(test_password)
        assert encrypted != test_password
        assert isinstance(encrypted, str)
        
        # Verify it's valid base64
        try:
            base64.b64decode(encrypted)
        except Exception:
            pytest.fail("Encrypted password is not valid base64")

        # Test decryption
        decrypted = crypto_manager.decrypt_password(encrypted)
        assert decrypted == test_password

    def test_encryption_with_special_chars(self, crypto_manager: CryptoManager) -> None:
        """Test encryption/decryption with special characters.

        Args:
            crypto_manager: Initialized crypto manager
        """
        test_passwords = [
            "Password!@#$%^&*()",
            "パスワード123",
            "Пароль!@#",
            "Password\n\t\r",
            "🔒Password🔑"
        ]

        for password in test_passwords:
            encrypted = crypto_manager.encrypt_password(password)
            decrypted = crypto_manager.decrypt_password(encrypted)
            assert decrypted == password

    def test_invalid_decryption(self, crypto_manager: CryptoManager) -> None:
        """Test handling of invalid encrypted data.

        Args:
            crypto_manager: Initialized crypto manager
        """
        invalid_data = [
            "",
            "not-base64",
            base64.b64encode(b"not-encrypted").decode(),
            "YWJjZGVm"  # valid base64 but not encrypted
        ]

        for data in invalid_data:
            with pytest.raises(ValueError, match="Decryption failed"):
                crypto_manager.decrypt_password(data)

    def test_key_persistence(self, temp_key_path: Path) -> None:
        """Test that keys persist between manager instances.

        Args:
            temp_key_path: Temporary key storage path
        """
        # Create first instance and encrypt
        manager1 = CryptoManager()
        test_password = "TestPassword123!"
        encrypted = manager1.encrypt_password(test_password)

        # Create second instance and decrypt
        manager2 = CryptoManager()
        decrypted = manager2.decrypt_password(encrypted)
        assert decrypted == test_password

    def test_key_backup_and_restore(
        self,
        crypto_manager: CryptoManager,
        tmp_path: Path
    ) -> None:
        """Test key backup and restore functionality.

        Args:
            crypto_manager: Initialized crypto manager
            tmp_path: Pytest temporary path
        """
        # Encrypt with original keys
        test_password = "BackupTest123!"
        encrypted = crypto_manager.encrypt_password(test_password)

        # Backup keys
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        import shutil
        shutil.copy2(crypto_manager.private_key_path, backup_dir)
        shutil.copy2(crypto_manager.public_key_path, backup_dir)

        # Generate new keys
        crypto_manager._generate_key_pair()

        # Verify old encrypted data can't be decrypted
        with pytest.raises(ValueError):
            crypto_manager.decrypt_password(encrypted)

        # Restore keys
        shutil.copy2(backup_dir / "private.pem", crypto_manager.private_key_path)
        shutil.copy2(backup_dir / "public.pem", crypto_manager.public_key_path)
        crypto_manager.private_key, crypto_manager.public_key = (
            crypto_manager._load_or_generate_keys()
        )

        # Verify restored keys can decrypt
        decrypted = crypto_manager.decrypt_password(encrypted)
        assert decrypted == test_password