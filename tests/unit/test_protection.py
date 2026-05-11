"""Unit tests for protection strategies."""

import pytest

from src.policy.policy_parser import ProtectionOptions
from src.protection.aes256_encryption import (
    AES256Encryption,
    DecryptionError,
)
from src.protection.base_protection import ProtectionRegistry
from src.protection.masking import Masking, Redaction
from src.protection.sha256_hashing import SHA256Hashing
from src.protection.tokenization import (
    Tokenization,
    TokenVault,
    clear_global_vault,
)

pytestmark = pytest.mark.unit


class TestProtectionRegistry:
    """Tests for protection registry."""

    def test_get_registered_strategy(self):
        strategy = ProtectionRegistry.get('aes256_encrypt')
        assert isinstance(strategy, AES256Encryption)

    def test_get_unknown_strategy_raises(self):
        with pytest.raises(KeyError, match="Unknown protection method"):
            ProtectionRegistry.get('unknown_method')

    def test_get_available_methods(self):
        methods = ProtectionRegistry.get_available_methods()
        for expected in ('aes256_encrypt', 'sha256_hash', 'masking',
                         'tokenization', 'redact'):
            assert expected in methods

    def test_is_registered(self):
        assert ProtectionRegistry.is_registered('masking') is True
        assert ProtectionRegistry.is_registered('unknown') is False


class TestAES256Encryption:
    """Tests for AES-256 encryption."""

    @pytest.fixture
    def encryption(self):
        return AES256Encryption()

    def test_encrypt_decrypt_roundtrip(self, encryption):
        original = "sensitive@email.com"
        encrypted = encryption.protect(original)
        decrypted = encryption.unprotect(encrypted)

        assert encrypted != original
        assert encrypted.startswith('ENC:')
        assert decrypted == original

    def test_encrypt_empty_string(self, encryption):
        assert encryption.protect("") == ""

    def test_encrypt_produces_different_ciphertexts(self, encryption):
        plaintext = "test value"
        assert encryption.protect(plaintext) != encryption.protect(plaintext)

    def test_decrypt_invalid_format(self, encryption):
        with pytest.raises(DecryptionError, match="not appear to be encrypted"):
            encryption.unprotect("not encrypted")

    def test_is_reversible(self, encryption):
        assert encryption.is_reversible is True

    def test_method_name(self, encryption):
        assert encryption.method_name == 'aes256_encrypt'

    def test_custom_key_roundtrip(self):
        key = AES256Encryption.generate_key()
        enc1 = AES256Encryption(encryption_key=key)
        enc2 = AES256Encryption(encryption_key=key)

        encrypted = enc1.protect("test")
        decrypted = enc2.unprotect(encrypted)

        assert decrypted == "test"

    def test_key_generation_size(self):
        assert len(AES256Encryption.generate_key()) == 32

    def test_key_base64_roundtrip(self):
        key = AES256Encryption.generate_key()
        encoded = AES256Encryption.key_to_base64(key)
        assert AES256Encryption.key_from_base64(encoded) == key


class TestSHA256Hashing:
    """Tests for SHA-256 hashing."""

    @pytest.fixture
    def hashing(self):
        return SHA256Hashing()

    def test_hash_produces_consistent_output(self, hashing):
        value = "test@example.com"
        h1 = hashing.protect(value)
        h2 = hashing.protect(value)
        assert h1 == h2
        assert h1.startswith('HASH:')

    def test_hash_different_inputs(self, hashing):
        assert hashing.protect("v1") != hashing.protect("v2")

    def test_hash_empty_string(self, hashing):
        assert hashing.protect("") == ""

    def test_is_not_reversible(self, hashing):
        assert hashing.is_reversible is False

    def test_unprotect_raises(self, hashing):
        with pytest.raises(NotImplementedError, match="not reversible"):
            hashing.unprotect("HASH:abc123")

    def test_verify_correct_value(self, hashing):
        value = "test@example.com"
        hashed = hashing.protect(value)
        assert hashing.verify(value, hashed) is True

    def test_verify_incorrect_value(self, hashing):
        hashed = hashing.protect("original")
        assert hashing.verify("different", hashed) is False

    def test_salted_hashes_differ(self):
        h1 = SHA256Hashing(salt="salt1").protect("value")
        h2 = SHA256Hashing(salt="salt2").protect("value")
        assert h1 != h2


class TestMasking:
    """Tests for masking protection."""

    def test_mask_right(self):
        result = Masking(ProtectionOptions(visible_chars=4, direction='right')).protect("1234567890")
        assert result == "******7890"

    def test_mask_left(self):
        result = Masking(ProtectionOptions(visible_chars=4, direction='left')).protect("1234567890")
        assert result == "1234******"

    def test_mask_center(self):
        result = Masking(ProtectionOptions(visible_chars=4, direction='center')).protect("1234567890")
        assert result == "***4567***"

    def test_mask_custom_char(self):
        result = Masking(ProtectionOptions(mask_char='X', visible_chars=4)).protect("1234567890")
        assert result == "XXXXXX7890"

    def test_mask_short_value(self):
        result = Masking(ProtectionOptions(visible_chars=10)).protect("short")
        assert result == "*****"

    def test_mask_empty_string(self):
        assert Masking().protect("") == ""

    def test_is_not_reversible(self):
        assert Masking().is_reversible is False


class TestRedaction:
    """Tests for redaction protection."""

    def test_redact_value(self):
        assert Redaction().protect("sensitive data") == "[REDACTED]"

    def test_redact_empty_string(self):
        assert Redaction().protect("") == ""


class TestTokenization:
    """Tests for tokenization protection."""

    @pytest.fixture(autouse=True)
    def _clear_vault(self):
        clear_global_vault()
        yield
        clear_global_vault()

    @pytest.fixture
    def tokenization(self):
        return Tokenization()

    def test_tokenize_value(self, tokenization):
        result = tokenization.protect("sensitive@email.com")
        assert result.startswith("TOK_")
        assert len(result) > len("TOK_")

    def test_tokenize_same_value_returns_same_token(self, tokenization):
        assert tokenization.protect("v") == tokenization.protect("v")

    def test_detokenize_returns_original(self, tokenization):
        original = "sensitive data"
        token = tokenization.protect(original)
        assert tokenization.unprotect(token) == original

    def test_is_reversible(self, tokenization):
        assert tokenization.is_reversible is True

    def test_detokenize_unknown_token_raises(self, tokenization):
        with pytest.raises(ValueError, match="Token not found"):
            tokenization.unprotect("TOK_UNKNOWN123456")

    def test_detokenize_invalid_format_raises(self, tokenization):
        with pytest.raises(ValueError, match="Invalid token format"):
            tokenization.unprotect("XXX_BADPREFIX")

    def test_custom_prefix_via_options(self):
        tokenization = Tokenization(ProtectionOptions(token_prefix="CUSTOM_"))
        assert tokenization.protect("value").startswith("CUSTOM_")


class TestTokenVault:
    """Tests for token vault."""

    @pytest.fixture
    def vault(self):
        return TokenVault()

    def test_store_and_retrieve(self, vault):
        vault.store("TOKEN123", "original value")
        assert vault.get_value("TOKEN123") == "original value"
        assert vault.get_token("original value") == "TOKEN123"

    def test_exists(self, vault):
        vault.store("TOKEN", "value")
        assert vault.exists("TOKEN") is True
        assert vault.exists("OTHER") is False

    def test_clear(self, vault):
        vault.store("T1", "V1")
        vault.store("T2", "V2")
        vault.clear()
        assert vault.size() == 0

    def test_size(self, vault):
        assert vault.size() == 0
        vault.store("T1", "V1")
        assert vault.size() == 1
