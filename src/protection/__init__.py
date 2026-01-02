"""Protection strategies package."""

from src.protection.aes256_encryption import (
    AES256Encryption,
    DecryptionError,
    EncryptionError,
)
from src.protection.base_protection import (
    BaseProtection,
    ProtectionRegistry,
    ProtectionResult,
    register_protection,
)
from src.protection.masking import (
    CreditCardMasking,
    EmailMasking,
    Masking,
    PhoneMasking,
    Redaction,
)
from src.protection.sha256_hashing import SHA256Hashing, SHA512Hashing
from src.protection.tokenization import (
    FormatPreservingTokenization,
    Tokenization,
    TokenVault,
    UUIDTokenization,
    clear_global_vault,
    get_global_vault,
)

__all__ = [
    'BaseProtection',
    'ProtectionResult',
    'ProtectionRegistry',
    'register_protection',
    'AES256Encryption',
    'EncryptionError',
    'DecryptionError',
    'SHA256Hashing',
    'SHA512Hashing',
    'Masking',
    'Redaction',
    'EmailMasking',
    'PhoneMasking',
    'CreditCardMasking',
    'Tokenization',
    'UUIDTokenization',
    'FormatPreservingTokenization',
    'TokenVault',
    'get_global_vault',
    'clear_global_vault',
]
