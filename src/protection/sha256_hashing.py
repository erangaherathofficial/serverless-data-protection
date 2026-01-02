"""SHA-256 hashing protection strategy."""

import hashlib
import hmac
import os
import secrets
from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


@register_protection('sha256_hash')
class SHA256Hashing(BaseProtection):
    """SHA-256 hashing protection strategy.

    Provides one-way cryptographic hashing for PII pseudonymization.
    Supports optional HMAC with secret key for keyed hashing.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        salt: Optional[str] = None,
        use_hmac: bool = False,
        hmac_key: Optional[bytes] = None,
        truncate_length: Optional[int] = None
    ) -> None:
        """Initialize SHA-256 hashing.

        Args:
            options: Protection options
            salt: Optional salt prefix for hashing
            use_hmac: Whether to use HMAC-SHA256
            hmac_key: Secret key for HMAC (generated if None and use_hmac=True)
            truncate_length: Truncate hash to this many characters (None = full hash)
        """
        super().__init__(options)
        self._salt = salt or os.environ.get('HASH_SALT', '')
        self._use_hmac = use_hmac
        self._truncate_length = truncate_length

        if use_hmac:
            if hmac_key:
                self._hmac_key = hmac_key
            else:
                env_key = os.environ.get('HMAC_KEY')
                if env_key:
                    self._hmac_key = env_key.encode('utf-8')
                else:
                    self._hmac_key = secrets.token_bytes(32)
        else:
            self._hmac_key = None

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'sha256_hash'

    @property
    def is_reversible(self) -> bool:
        """SHA-256 hashing is not reversible."""
        return False

    def protect(self, value: str) -> str:
        """Hash a value using SHA-256.

        Args:
            value: The plaintext value

        Returns:
            Hexadecimal hash string with prefix
        """
        if not value:
            return value

        if self._use_hmac and self._hmac_key:
            hash_value = self._compute_hmac(value)
        else:
            hash_value = self._compute_hash(value)

        if self._truncate_length and self._truncate_length > 0:
            hash_value = hash_value[:self._truncate_length]

        return f"HASH:{hash_value}"

    def _compute_hash(self, value: str) -> str:
        """Compute SHA-256 hash with optional salt."""
        salted_value = f"{self._salt}{value}"
        hash_bytes = hashlib.sha256(salted_value.encode('utf-8')).digest()
        return hash_bytes.hex()

    def _compute_hmac(self, value: str) -> str:
        """Compute HMAC-SHA256."""
        salted_value = f"{self._salt}{value}"
        hash_bytes = hmac.new(
            self._hmac_key,
            salted_value.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return hash_bytes.hex()

    def verify(self, plaintext: str, hashed: str) -> bool:
        """Verify if plaintext matches a hash.

        Args:
            plaintext: Original value to verify
            hashed: Previously computed hash

        Returns:
            True if plaintext hashes to the same value
        """
        if not hashed.startswith('HASH:'):
            return False

        expected = self.protect(plaintext)
        return hmac.compare_digest(expected, hashed)

    def _get_metadata(self, original: str, protected: str) -> dict:
        """Get hashing metadata."""
        return {
            'original_length': len(original),
            'protected_length': len(protected),
            'algorithm': 'HMAC-SHA256' if self._use_hmac else 'SHA-256',
            'salted': bool(self._salt),
            'truncated': self._truncate_length is not None
        }

    @classmethod
    def generate_salt(cls, length: int = 16) -> str:
        """Generate a random salt string.

        Args:
            length: Length of salt in bytes

        Returns:
            Hexadecimal salt string
        """
        return secrets.token_hex(length)

    @classmethod
    def generate_hmac_key(cls, length: int = 32) -> bytes:
        """Generate a random HMAC key.

        Args:
            length: Length of key in bytes

        Returns:
            Random key bytes
        """
        return secrets.token_bytes(length)


@register_protection('sha512_hash')
class SHA512Hashing(BaseProtection):
    """SHA-512 hashing protection strategy.

    Provides stronger hashing with 512-bit output.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        salt: Optional[str] = None,
        truncate_length: Optional[int] = None
    ) -> None:
        """Initialize SHA-512 hashing.

        Args:
            options: Protection options
            salt: Optional salt prefix
            truncate_length: Truncate hash to this length
        """
        super().__init__(options)
        self._salt = salt or ''
        self._truncate_length = truncate_length

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'sha512_hash'

    @property
    def is_reversible(self) -> bool:
        """SHA-512 hashing is not reversible."""
        return False

    def protect(self, value: str) -> str:
        """Hash a value using SHA-512.

        Args:
            value: The plaintext value

        Returns:
            Hexadecimal hash string with prefix
        """
        if not value:
            return value

        salted_value = f"{self._salt}{value}"
        hash_bytes = hashlib.sha512(salted_value.encode('utf-8')).digest()
        hash_value = hash_bytes.hex()

        if self._truncate_length and self._truncate_length > 0:
            hash_value = hash_value[:self._truncate_length]

        return f"HASH512:{hash_value}"

    def verify(self, plaintext: str, hashed: str) -> bool:
        """Verify if plaintext matches a hash."""
        if not hashed.startswith('HASH512:'):
            return False

        expected = self.protect(plaintext)
        return hmac.compare_digest(expected, hashed)
