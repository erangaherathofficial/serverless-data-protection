"""AES-256 encryption protection strategy."""

import base64
import logging
import os
import secrets
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection

logger = logging.getLogger(__name__)

BLOCK_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16


class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


@register_protection('aes256_encrypt')
class AES256Encryption(BaseProtection):
    """AES-256 encryption protection strategy.

    Uses AES-256-CBC mode with PKCS7 padding.
    Optionally integrates with AWS KMS for key management.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        encryption_key: Optional[bytes] = None,
        use_kms: bool = False,
        kms_key_id: Optional[str] = None
    ) -> None:
        """Initialize AES-256 encryption.

        Args:
            options: Protection options
            encryption_key: 32-byte encryption key (generated if None)
            use_kms: Whether to use AWS KMS for key management
            kms_key_id: KMS key ID for envelope encryption
        """
        super().__init__(options)
        self._use_kms = use_kms
        self._kms_key_id = kms_key_id or os.environ.get('KMS_KEY_ID')

        if encryption_key:
            if len(encryption_key) != KEY_SIZE:
                raise ValueError(f"Encryption key must be {KEY_SIZE} bytes")
            self._key = encryption_key
        else:
            self._key = self._generate_or_fetch_key()

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'aes256_encrypt'

    @property
    def is_reversible(self) -> bool:
        """AES encryption is reversible."""
        return True

    def protect(self, value: str) -> str:
        """Encrypt a value using AES-256-CBC.

        Args:
            value: The plaintext value

        Returns:
            Base64-encoded encrypted value with IV prefix
        """
        if not value:
            return value

        try:
            iv = secrets.token_bytes(IV_SIZE)
            plaintext = self._pad(value.encode('utf-8'))

            cipher = Cipher(
                algorithms.AES(self._key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            combined = iv + ciphertext
            encoded = base64.b64encode(combined).decode('utf-8')

            return f"ENC:{encoded}"

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt value: {e}")

    def _do_unprotect(self, value: str) -> str:
        """Decrypt an AES-256 encrypted value.

        Args:
            value: Base64-encoded encrypted value

        Returns:
            Decrypted plaintext
        """
        if not value:
            return value

        if not value.startswith('ENC:'):
            raise DecryptionError("Value does not appear to be encrypted")

        try:
            encoded = value[4:]
            combined = base64.b64decode(encoded)

            if len(combined) < IV_SIZE + BLOCK_SIZE:
                raise DecryptionError("Encrypted data too short")

            iv = combined[:IV_SIZE]
            ciphertext = combined[IV_SIZE:]

            cipher = Cipher(
                algorithms.AES(self._key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            plaintext = self._unpad(padded)
            return plaintext.decode('utf-8')

        except DecryptionError:
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt value: {e}")

    def _pad(self, data: bytes) -> bytes:
        """Apply PKCS7 padding."""
        padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        """Remove PKCS7 padding."""
        if not data:
            return data

        padding_length = data[-1]

        if padding_length > BLOCK_SIZE or padding_length == 0:
            raise DecryptionError("Invalid padding")

        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                raise DecryptionError("Invalid padding")

        return data[:-padding_length]

    def _generate_or_fetch_key(self) -> bytes:
        """Generate or fetch encryption key."""
        if self._use_kms and self._kms_key_id:
            return self._fetch_key_from_kms()

        env_key = os.environ.get('ENCRYPTION_KEY')
        if env_key:
            key_bytes = base64.b64decode(env_key)
            if len(key_bytes) == KEY_SIZE:
                return key_bytes

        return secrets.token_bytes(KEY_SIZE)

    def _fetch_key_from_kms(self) -> bytes:
        """Fetch or generate data key using AWS KMS."""
        try:
            from src.aws.client_manager import get_client_manager

            client_manager = get_client_manager()
            response = client_manager.kms.generate_data_key(
                KeyId=self._kms_key_id,
                KeySpec='AES_256'
            )
            return response['Plaintext']

        except Exception as e:
            logger.warning(f"KMS key fetch failed: {e}. Using generated key.")
            return secrets.token_bytes(KEY_SIZE)

    def _get_metadata(self, original: str, protected: str) -> dict:
        """Get encryption metadata."""
        return {
            'original_length': len(original),
            'protected_length': len(protected),
            'algorithm': 'AES-256-CBC',
            'uses_kms': self._use_kms,
            'has_iv': True
        }

    def rotate_key(self, new_key: bytes) -> None:
        """Rotate the encryption key.

        Args:
            new_key: New 32-byte encryption key
        """
        if len(new_key) != KEY_SIZE:
            raise ValueError(f"New key must be {KEY_SIZE} bytes")
        self._key = new_key

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a new random encryption key.

        Returns:
            32-byte random key
        """
        return secrets.token_bytes(KEY_SIZE)

    @classmethod
    def key_to_base64(cls, key: bytes) -> str:
        """Convert key to base64 string for storage.

        Args:
            key: Encryption key bytes

        Returns:
            Base64-encoded string
        """
        return base64.b64encode(key).decode('utf-8')

    @classmethod
    def key_from_base64(cls, encoded: str) -> bytes:
        """Convert base64 string to key bytes.

        Args:
            encoded: Base64-encoded key

        Returns:
            Key bytes
        """
        return base64.b64decode(encoded)
