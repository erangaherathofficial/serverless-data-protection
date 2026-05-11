"""Masking protection strategy."""

from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


@register_protection('masking')
class Masking(BaseProtection):
    """Partial masking protection strategy.

    Replaces characters with a configurable mask character while preserving a
    configurable number of visible characters at one or both edges.
    """

    def __init__(self, options: Optional[ProtectionOptions] = None) -> None:
        super().__init__(options)
        self._mask_char = self._options.mask_char
        self._visible_chars = self._options.visible_chars
        self._direction = self._options.direction

    @property
    def method_name(self) -> str:
        return 'masking'

    @property
    def is_reversible(self) -> bool:
        return False

    def protect(self, value: str) -> str:
        if not value:
            return value

        length = len(value)

        if self._visible_chars <= 0 or length <= self._visible_chars:
            return self._mask_char * length

        if self._direction == 'left':
            return self._mask_left(value)
        if self._direction == 'center':
            return self._mask_center(value)
        return self._mask_right(value)

    def _mask_right(self, value: str) -> str:
        visible = value[-self._visible_chars:]
        mask_length = len(value) - self._visible_chars
        return self._mask_char * mask_length + visible

    def _mask_left(self, value: str) -> str:
        visible = value[:self._visible_chars]
        mask_length = len(value) - self._visible_chars
        return visible + self._mask_char * mask_length

    def _mask_center(self, value: str) -> str:
        length = len(value)
        start_mask = (length - self._visible_chars) // 2
        end_mask = length - self._visible_chars - start_mask
        return (
                self._mask_char * start_mask
                + value[start_mask:start_mask + self._visible_chars]
                + self._mask_char * end_mask
        )


@register_protection('redact')
class Redaction(BaseProtection):
    """Full redaction protection strategy.

    Replaces the entire value with a fixed redaction marker.
    """

    @property
    def method_name(self) -> str:
        return 'redact'

    @property
    def is_reversible(self) -> bool:
        return False

    def protect(self, value: str) -> str:
        if not value:
            return value
        return '[REDACTED]'
