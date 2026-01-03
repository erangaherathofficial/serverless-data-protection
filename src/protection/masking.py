"""Masking protection strategy."""

import re
from typing import Optional

from src.policy.policy_parser import ProtectionOptions
from src.protection.base_protection import BaseProtection, register_protection


@register_protection('masking')
class Masking(BaseProtection):
    """Partial masking protection strategy.

    Replaces characters with mask character while preserving
    a configurable number of visible characters.
    """

    def __init__(self, options: Optional[ProtectionOptions] = None) -> None:
        """Initialize masking.

        Args:
            options: Protection options with masking configuration
        """
        super().__init__(options)
        self._mask_char = self._options.mask_char
        self._visible_chars = self._options.visible_chars
        self._direction = self._options.direction

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'masking'

    @property
    def is_reversible(self) -> bool:
        """Masking is not reversible."""
        return False

    def protect(self, value: str) -> str:
        """Apply masking to a value.

        Args:
            value: The value to mask

        Returns:
            Masked value with visible characters preserved
        """
        if not value:
            return value

        length = len(value)

        if length <= self._visible_chars:
            return self._mask_char * length

        if self._direction == 'right':
            return self._mask_right(value)
        elif self._direction == 'left':
            return self._mask_left(value)
        elif self._direction == 'center':
            return self._mask_center(value)
        else:
            return self._mask_right(value)

    def _mask_right(self, value: str) -> str:
        """Mask keeping rightmost characters visible."""
        visible = value[-self._visible_chars:]
        mask_length = len(value) - self._visible_chars
        return self._mask_char * mask_length + visible

    def _mask_left(self, value: str) -> str:
        """Mask keeping leftmost characters visible."""
        visible = value[:self._visible_chars]
        mask_length = len(value) - self._visible_chars
        return visible + self._mask_char * mask_length

    def _mask_center(self, value: str) -> str:
        """Mask keeping center characters visible, masking edges."""
        length = len(value)
        if length <= self._visible_chars:
            return self._mask_char * length

        start_mask = (length - self._visible_chars) // 2
        end_mask = length - self._visible_chars - start_mask

        return (
                self._mask_char * start_mask
                + value[start_mask:start_mask + self._visible_chars]
                + self._mask_char * end_mask
        )

    def _get_metadata(self, original: str, protected: str) -> dict:
        """Get masking metadata."""
        return {
            'original_length': len(original),
            'protected_length': len(protected),
            'mask_char': self._mask_char,
            'visible_chars': self._visible_chars,
            'direction': self._direction
        }


@register_protection('redact')
class Redaction(BaseProtection):
    """Full redaction protection strategy.

    Completely replaces value with redaction marker.
    """

    DEFAULT_REDACTION = '[REDACTED]'

    def __init__(
            self,
            options: Optional[ProtectionOptions] = None,
            redaction_text: Optional[str] = None
    ) -> None:
        """Initialize redaction.

        Args:
            options: Protection options
            redaction_text: Custom redaction replacement text
        """
        super().__init__(options)
        self._redaction_text = redaction_text or self.DEFAULT_REDACTION

    @property
    def method_name(self) -> str:
        """Get the protection method name."""
        return 'redact'

    @property
    def is_reversible(self) -> bool:
        """Redaction is not reversible."""
        return False

    def protect(self, value: str) -> str:
        """Redact a value completely.

        Args:
            value: The value to redact

        Returns:
            Redaction marker
        """
        if not value:
            return value

        return self._redaction_text

    def _get_metadata(self, original: str, protected: str) -> dict:
        """Get redaction metadata."""
        return {
            'original_length': len(original),
            'redaction_text': self._redaction_text
        }


class EmailMasking(Masking):
    """Specialized masking for email addresses.

    Preserves domain while masking local part.
    """

    def protect(self, value: str) -> str:
        """Mask email address preserving domain.

        Args:
            value: Email address to mask

        Returns:
            Masked email with visible domain
        """
        if not value or '@' not in value:
            return super().protect(value)

        local_part, domain = value.rsplit('@', 1)

        if len(local_part) <= 2:
            masked_local = self._mask_char * len(local_part)
        else:
            masked_local = (
                    local_part[0]
                    + self._mask_char * (len(local_part) - 2)
                    + local_part[-1]
            )

        return f"{masked_local}@{domain}"


class PhoneMasking(Masking):
    """Specialized masking for phone numbers.

    Preserves formatting while masking digits.
    """

    def protect(self, value: str) -> str:
        """Mask phone number preserving format.

        Args:
            value: Phone number to mask

        Returns:
            Masked phone with last digits visible
        """
        if not value:
            return value

        digits = re.findall(r'\d', value)
        if len(digits) <= self._visible_chars:
            return re.sub(r'\d', self._mask_char, value)

        result = list(value)
        digit_count = 0
        visible_start = len(digits) - self._visible_chars

        for i, char in enumerate(result):
            if char.isdigit():
                if digit_count < visible_start:
                    result[i] = self._mask_char
                digit_count += 1

        return ''.join(result)


class CreditCardMasking(Masking):
    """Specialized masking for credit card numbers.

    Shows only last 4 digits (PCI DSS compliant).
    """

    def __init__(self, options: Optional[ProtectionOptions] = None) -> None:
        """Initialize credit card masking with 4 visible chars."""
        super().__init__(options)
        self._visible_chars = 4
        self._direction = 'right'

    def protect(self, value: str) -> str:
        """Mask credit card number showing last 4 digits.

        Args:
            value: Credit card number

        Returns:
            Masked card number
        """
        if not value:
            return value

        digits = re.sub(r'\D', '', value)

        if len(digits) < 13:
            return super().protect(value)

        visible = digits[-4:]
        masked = self._mask_char * (len(digits) - 4) + visible

        if '-' in value or ' ' in value:
            return self._format_masked(masked, value)

        return masked

    def _format_masked(self, masked: str, original: str) -> str:
        """Apply original formatting to masked value."""
        separator = '-' if '-' in original else ' '
        parts = []

        for i in range(0, len(masked), 4):
            parts.append(masked[i:i + 4])

        return separator.join(parts)
