"""SHA-256 hashing protection strategy."""

import hashlib
import hmac
import os
from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


@register_protection('sha256_hash')
class SHA256Hashing(BaseProtection):
    """SHA-256 hashing protection strategy.

    Provides one-way cryptographic hashing for PII pseudonymization. The
    salt is read from the ``HASH_SALT`` environment variable (or the
    ``salt`` constructor argument) and prepended to every value.
    """

    def __init__(
            self,
            options: Optional[ProtectionOptions] = None,
            salt: Optional[str] = None,
    ) -> None:
        super().__init__(options)
        self._salt = salt if salt is not None else os.environ.get('HASH_SALT', '')

    @property
    def method_name(self) -> str:
        return 'sha256_hash'

    @property
    def is_reversible(self) -> bool:
        return False

    def protect(self, value: str) -> str:
        if not value:
            return value
        salted = f"{self._salt}{value}"
        digest = hashlib.sha256(salted.encode('utf-8')).hexdigest()
        return f"HASH:{digest}"

    def verify(self, plaintext: str, hashed: str) -> bool:
        """Return True if ``plaintext`` hashes to ``hashed`` under this strategy."""
        if not hashed.startswith('HASH:'):
            return False
        return hmac.compare_digest(self.protect(plaintext), hashed)
