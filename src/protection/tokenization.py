"""Tokenization protection strategy."""

import hashlib
import secrets
import string
import uuid
from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


class TokenVault:
    """In-memory token vault for storing token-value mappings.

    In production, this would be replaced with a persistent
    secure storage like DynamoDB or a dedicated tokenization service.
    """

    def __init__(self) -> None:
        self._token_to_value: dict[str, str] = {}
        self._value_to_token: dict[str, str] = {}

    def store(self, token: str, value: str) -> None:
        """Store token-value mapping."""
        self._token_to_value[token] = value
        self._value_to_token[value] = token

    def get_value(self, token: str) -> Optional[str]:
        """Get original value for token."""
        return self._token_to_value.get(token)

    def get_token(self, value: str) -> Optional[str]:
        """Get existing token for value."""
        return self._value_to_token.get(value)

    def exists(self, token: str) -> bool:
        """Check if token exists."""
        return token in self._token_to_value

    def clear(self) -> None:
        """Clear all stored mappings."""
        self._token_to_value.clear()
        self._value_to_token.clear()

    def size(self) -> int:
        """Get number of stored tokens."""
        return len(self._token_to_value)


_global_vault = TokenVault()


@register_protection('tokenization')
class Tokenization(BaseProtection):
    """Tokenization protection strategy.

    Replaces sensitive values with non-sensitive surrogate tokens.
    Supports reversible detokenization when vault is available.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        vault: Optional[TokenVault] = None,
        token_prefix: Optional[str] = None,
        token_length: int = 16,
        deterministic: bool = False
    ) -> None:
        """Initialize tokenization.

        Args:
            options: Protection options
            vault: Token vault for storage (uses global if None)
            token_prefix: Prefix for generated tokens
            token_length: Length of random token part
            deterministic: Whether same input produces same token
        """
        super().__init__(options)
        self._vault = vault or _global_vault
        self._token_prefix = token_prefix or self._options.token_prefix
        self._token_length = token_length
        self._deterministic = deterministic

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'tokenization'

    @property
    def is_reversible(self) -> bool:
        """Tokenization is reversible with vault."""
        return True

    def protect(self, value: str) -> str:
        """Tokenize a value.

        Args:
            value: The value to tokenize

        Returns:
            Token replacing the original value
        """
        if not value:
            return value

        existing_token = self._vault.get_token(value)
        if existing_token:
            return existing_token

        token = self._generate_token(value)

        while self._vault.exists(token):
            token = self._generate_token(value, force_random=True)

        self._vault.store(token, value)
        return token

    def _do_unprotect(self, value: str) -> str:
        """Detokenize a token back to original value.

        Args:
            value: The token to detokenize

        Returns:
            Original value

        Raises:
            ValueError: If token not found in vault
        """
        if not value:
            return value

        if not value.startswith(self._token_prefix):
            raise ValueError(f"Invalid token format: {value}")

        original = self._vault.get_value(value)
        if original is None:
            raise ValueError(f"Token not found in vault: {value}")

        return original

    def _generate_token(self, value: str, force_random: bool = False) -> str:
        """Generate a token for a value."""
        if self._deterministic and not force_random:
            hash_value = hashlib.sha256(value.encode()).hexdigest()
            token_part = hash_value[:self._token_length].upper()
        else:
            chars = string.ascii_uppercase + string.digits
            token_part = ''.join(
                secrets.choice(chars) for _ in range(self._token_length)
            )

        return f"{self._token_prefix}{token_part}"

    def _get_metadata(self, original: str, protected: str) -> dict:
        """Get tokenization metadata."""
        return {
            'original_length': len(original),
            'token_length': len(protected),
            'prefix': self._token_prefix,
            'deterministic': self._deterministic,
            'vault_size': self._vault.size()
        }

    @property
    def vault(self) -> TokenVault:
        """Get the token vault."""
        return self._vault


@register_protection('uuid_tokenization')
class UUIDTokenization(BaseProtection):
    """UUID-based tokenization strategy.

    Uses UUID v4 for tokens, ensuring global uniqueness.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        vault: Optional[TokenVault] = None,
        prefix: str = 'UUID_'
    ) -> None:
        """Initialize UUID tokenization.

        Args:
            options: Protection options
            vault: Token vault for storage
            prefix: Prefix for tokens
        """
        super().__init__(options)
        self._vault = vault or _global_vault
        self._prefix = prefix

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'uuid_tokenization'

    @property
    def is_reversible(self) -> bool:
        """UUID tokenization is reversible with vault."""
        return True

    def protect(self, value: str) -> str:
        """Tokenize with UUID.

        Args:
            value: Value to tokenize

        Returns:
            UUID-based token
        """
        if not value:
            return value

        existing = self._vault.get_token(value)
        if existing:
            return existing

        token = f"{self._prefix}{uuid.uuid4().hex.upper()}"
        self._vault.store(token, value)
        return token

    def _do_unprotect(self, value: str) -> str:
        """Detokenize UUID token."""
        if not value:
            return value

        original = self._vault.get_value(value)
        if original is None:
            raise ValueError(f"Token not found: {value}")

        return original


class FormatPreservingTokenization(BaseProtection):
    """Format-preserving tokenization.

    Generates tokens that match the format of the original value.
    Useful for maintaining data type compatibility.
    """

    def __init__(
        self,
        options: Optional[ProtectionOptions] = None,
        vault: Optional[TokenVault] = None
    ) -> None:
        """Initialize format-preserving tokenization."""
        super().__init__(options)
        self._vault = vault or _global_vault

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'format_preserving_tokenization'

    @property
    def is_reversible(self) -> bool:
        """Format-preserving tokenization is reversible."""
        return True

    def protect(self, value: str) -> str:
        """Tokenize preserving format.

        Args:
            value: Value to tokenize

        Returns:
            Token with same character format
        """
        if not value:
            return value

        existing = self._vault.get_token(value)
        if existing:
            return existing

        token = self._generate_format_preserving_token(value)

        while self._vault.exists(token):
            token = self._generate_format_preserving_token(value)

        self._vault.store(token, value)
        return token

    def _generate_format_preserving_token(self, value: str) -> str:
        """Generate token matching format of value."""
        result = []

        for char in value:
            if char.isdigit():
                result.append(secrets.choice(string.digits))
            elif char.isalpha():
                if char.isupper():
                    result.append(secrets.choice(string.ascii_uppercase))
                else:
                    result.append(secrets.choice(string.ascii_lowercase))
            else:
                result.append(char)

        return ''.join(result)

    def _do_unprotect(self, value: str) -> str:
        """Detokenize format-preserving token."""
        original = self._vault.get_value(value)
        if original is None:
            raise ValueError(f"Token not found: {value}")
        return original


def get_global_vault() -> TokenVault:
    """Get the global token vault."""
    return _global_vault


def clear_global_vault() -> None:
    """Clear the global token vault."""
    _global_vault.clear()
