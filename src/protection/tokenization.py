"""Tokenization protection strategy."""

import secrets
import string
from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


class TokenVault:
    """In-memory token vault.

    Maps generated tokens to their original values for the lifetime of the
    Lambda execution context. Production deployments would back this with a
    persistent store (DynamoDB, dedicated tokenization service, etc.).
    """

    def __init__(self) -> None:
        self._token_to_value: dict[str, str] = {}
        self._value_to_token: dict[str, str] = {}

    def store(self, token: str, value: str) -> None:
        self._token_to_value[token] = value
        self._value_to_token[value] = token

    def get_value(self, token: str) -> Optional[str]:
        return self._token_to_value.get(token)

    def get_token(self, value: str) -> Optional[str]:
        return self._value_to_token.get(value)

    def exists(self, token: str) -> bool:
        return token in self._token_to_value

    def clear(self) -> None:
        self._token_to_value.clear()
        self._value_to_token.clear()

    def size(self) -> int:
        return len(self._token_to_value)


_global_vault = TokenVault()


def clear_global_vault() -> None:
    """Reset the process-global token vault (test helper)."""
    _global_vault.clear()


@register_protection('tokenization')
class Tokenization(BaseProtection):
    """Tokenization protection strategy.

    Replaces sensitive values with random surrogate tokens stored in the
    in-memory vault for the lifetime of the Lambda invocation.
    """

    TOKEN_LENGTH = 16
    _ALPHABET = string.ascii_uppercase + string.digits

    def __init__(
            self,
            options: Optional[ProtectionOptions] = None,
            vault: Optional[TokenVault] = None,
    ) -> None:
        super().__init__(options)
        self._vault = vault or _global_vault
        self._token_prefix = self._options.token_prefix

    @property
    def method_name(self) -> str:
        return 'tokenization'

    @property
    def is_reversible(self) -> bool:
        return True

    def protect(self, value: str) -> str:
        if not value:
            return value

        existing_token = self._vault.get_token(value)
        if existing_token:
            return existing_token

        token = self._generate_token()
        while self._vault.exists(token):
            token = self._generate_token()

        self._vault.store(token, value)
        return token

    def _do_unprotect(self, value: str) -> str:
        if not value:
            return value
        if not value.startswith(self._token_prefix):
            raise ValueError(f"Invalid token format: {value}")
        original = self._vault.get_value(value)
        if original is None:
            raise ValueError(f"Token not found in vault: {value}")
        return original

    def _generate_token(self) -> str:
        body = ''.join(
            secrets.choice(self._ALPHABET) for _ in range(self.TOKEN_LENGTH)
        )
        return f"{self._token_prefix}{body}"
