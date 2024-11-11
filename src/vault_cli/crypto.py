"""Cryptographic operations module for password encryption and key management.

This module handles:
- RSA key pair generation and management
- Password encryption and decryption
- Secure key storage with appropriate file permissions

The module uses RSA-2048 encryption with OAEP padding for secure password storage.
"""

import os
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey
)

class CryptoManager:
    """Manages cryptographic operations and key handling.

    This class handles:
    - RSA key pair generation and storage
    - Key loading and management
    - Password encryption and decryption
    - Secure file permissions
    """

    def __init__(self) -> None:
        """Initialize the crypto manager and set up key paths.

        Creates necessary directories and loads or generates key pairs.
        Sets appropriate file permissions on Unix-like systems.

        Raises:
            OSError: If directory creation or permission setting fails
        """
        self.key_path: str = os.path.expanduser('~/.password_manager/')
        self.private_key_path: str = os.path.join(self.key_path, 'private.pem')
        self.public_key_path: str = os.path.join(self.key_path, 'public.pem')

        # Initialize key attributes
        self.private_key: RSAPrivateKey
        self.public_key: RSAPublicKey

        os.makedirs(self.key_path, exist_ok=True)
        self.private_key, self.public_key = self._load_or_generate_keys()

        if os.name != 'nt':  # Unix-like systems only
            os.chmod(self.key_path, 0o700)
            os.chmod(self.private_key_path, 0o600)
            os.chmod(self.public_key_path, 0o644)

    def _generate_key_pair(self) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        """Generate a new RSA key pair.

        Generates a 2048-bit RSA key pair with standard parameters.

        Returns:
            Tuple containing:
                - RSAPrivateKey: The private key object
                - RSAPublicKey: The public key object

        Raises:
            ValueError: If key generation fails
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            self._save_keys(private_key, public_key)
            return private_key, public_key
        except Exception as e:
            raise ValueError(f"Key generation failed: {str(e)}")

    def _save_keys(self, private_key: RSAPrivateKey, public_key: RSAPublicKey) -> None:
        """Save the key pair to files.

        Args:
            private_key: The RSA private key to save
            public_key: The RSA public key to save

        Raises:
            OSError: If writing keys to files fails
        """
        try:
            with open(self.private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(self.public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        except Exception as e:
            raise OSError(f"Failed to save keys: {str(e)}")

    def encrypt_password(self, password: str) -> str:
        """Encrypt a password using RSA encryption with OAEP padding.

        Args:
            password: The plaintext password to encrypt

        Returns:
            str: Base64 encoded encrypted password

        Raises:
            ValueError: If encryption fails or input is invalid
        """
        try:
            encrypted = self.public_key.encrypt(
                password.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt an encrypted password.

        Args:
            encrypted_password: The base64 encoded encrypted password

        Returns:
            str: The decrypted password in plaintext

        Raises:
            ValueError: If decryption fails or input is invalid
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_password)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")