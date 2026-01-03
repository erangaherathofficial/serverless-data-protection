"""Unit tests for protection strategies."""

import pytest

from src.policy.policy_parser import ProtectionOptions
from src.protection.aes256_encryption import (
    AES256Encryption,
    DecryptionError,
)
from src.protection.base_protection import ProtectionRegistry
from src.protection.masking import (
    CreditCardMasking,
    EmailMasking,
    Masking,
    PhoneMasking,
    Redaction,
)
from src.protection.sha256_hashing import SHA256Hashing
from src.protection.tokenization import (
    FormatPreservingTokenization,
    Tokenization,
    TokenVault,
    UUIDTokenization,
    clear_global_vault,
)


class TestProtectionRegistry:
    """Tests for protection registry."""

    def test_get_registered_strategy(self):
        """Test getting registered strategies."""
        strategy = ProtectionRegistry.get('aes256_encrypt')
        assert isinstance(strategy, AES256Encryption)

    def test_get_unknown_strategy_raises(self):
        """Test unknown strategy raises error."""
        with pytest.raises(KeyError):
            ProtectionRegistry.get('unknown_method')

    def test_get_available_methods(self):
        """Test listing available methods."""
        methods = ProtectionRegistry.get_available_methods()
        assert 'aes256_encrypt' in methods
        assert 'sha256_hash' in methods
        assert 'masking' in methods
        assert 'tokenization' in methods

    def test_is_registered(self):
        """Test checking registration."""
        assert ProtectionRegistry.is_registered('masking') is True
        assert ProtectionRegistry.is_registered('unknown') is False


class TestAES256Encryption:
    """Tests for AES-256 encryption."""

    @pytest.fixture
    def encryption(self):
        """Create encryption instance."""
        return AES256Encryption()

    def test_encrypt_decrypt_roundtrip(self, encryption):
        """Test encryption and decryption roundtrip."""
        original = "sensitive@email.com"
        encrypted = encryption.protect(original)
        decrypted = encryption.unprotect(encrypted)

        assert encrypted != original
        assert encrypted.startswith('ENC:')
        assert decrypted == original

    def test_encrypt_empty_string(self, encryption):
        """Test encrypting empty string."""
        result = encryption.protect("")
        assert result == ""

    def test_encrypt_produces_different_ciphertexts(self, encryption):
        """Test same plaintext produces different ciphertexts (IV)."""
        plaintext = "test value"
        encrypted1 = encryption.protect(plaintext)
        encrypted2 = encryption.protect(plaintext)

        assert encrypted1 != encrypted2

    def test_decrypt_invalid_format(self, encryption):
        """Test decrypting invalid format raises error."""
        with pytest.raises(DecryptionError):
            encryption.unprotect("not encrypted")

    def test_is_reversible(self, encryption):
        """Test is_reversible property."""
        assert encryption.is_reversible is True

    def test_method_name(self, encryption):
        """Test method name."""
        assert encryption.method_name == 'aes256_encrypt'

    def test_custom_key(self):
        """Test using custom encryption key."""
        key = AES256Encryption.generate_key()
        enc1 = AES256Encryption(encryption_key=key)
        enc2 = AES256Encryption(encryption_key=key)

        encrypted = enc1.protect("test")
        decrypted = enc2.unprotect(encrypted)

        assert decrypted == "test"

    def test_key_generation(self):
        """Test key generation."""
        key = AES256Encryption.generate_key()
        assert len(key) == 32

    def test_key_base64_conversion(self):
        """Test key base64 encoding/decoding."""
        key = AES256Encryption.generate_key()
        encoded = AES256Encryption.key_to_base64(key)
        decoded = AES256Encryption.key_from_base64(encoded)
        assert key == decoded


class TestSHA256Hashing:
    """Tests for SHA-256 hashing."""

    @pytest.fixture
    def hashing(self):
        """Create hashing instance."""
        return SHA256Hashing()

    def test_hash_produces_consistent_output(self, hashing):
        """Test same input produces same hash."""
        value = "test@example.com"
        hash1 = hashing.protect(value)
        hash2 = hashing.protect(value)

        assert hash1 == hash2
        assert hash1.startswith('HASH:')

    def test_hash_different_inputs(self, hashing):
        """Test different inputs produce different hashes."""
        hash1 = hashing.protect("value1")
        hash2 = hashing.protect("value2")

        assert hash1 != hash2

    def test_hash_empty_string(self, hashing):
        """Test hashing empty string."""
        result = hashing.protect("")
        assert result == ""

    def test_is_not_reversible(self, hashing):
        """Test is_reversible property."""
        assert hashing.is_reversible is False

    def test_unprotect_raises_error(self, hashing):
        """Test unprotect raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            hashing.unprotect("HASH:abc123")

    def test_verify_correct_value(self, hashing):
        """Test verifying correct value."""
        value = "test@example.com"
        hashed = hashing.protect(value)
        assert hashing.verify(value, hashed) is True

    def test_verify_incorrect_value(self, hashing):
        """Test verifying incorrect value."""
        hashed = hashing.protect("original")
        assert hashing.verify("different", hashed) is False

    def test_salted_hashing(self):
        """Test hashing with salt."""
        hash1 = SHA256Hashing(salt="salt1")
        hash2 = SHA256Hashing(salt="salt2")

        result1 = hash1.protect("value")
        result2 = hash2.protect("value")

        assert result1 != result2

    def test_hmac_hashing(self):
        """Test HMAC-SHA256 hashing."""
        hashing = SHA256Hashing(use_hmac=True)
        result = hashing.protect("test value")
        assert result.startswith('HASH:')

    def test_truncated_hash(self):
        """Test truncated hash output."""
        hashing = SHA256Hashing(truncate_length=16)
        result = hashing.protect("test")
        assert len(result) == len('HASH:') + 16


class TestMasking:
    """Tests for masking protection."""

    @pytest.fixture
    def masking(self):
        """Create masking instance with defaults."""
        return Masking()

    def test_mask_right(self):
        """Test masking keeping right chars visible."""
        options = ProtectionOptions(visible_chars=4, direction='right')
        masking = Masking(options)
        result = masking.protect("1234567890")
        assert result == "******7890"

    def test_mask_left(self):
        """Test masking keeping left chars visible."""
        options = ProtectionOptions(visible_chars=4, direction='left')
        masking = Masking(options)
        result = masking.protect("1234567890")
        assert result == "1234******"

    def test_mask_center(self):
        """Test masking keeping center chars visible."""
        options = ProtectionOptions(visible_chars=4, direction='center')
        masking = Masking(options)
        result = masking.protect("1234567890")
        assert result == "***4567***"

    def test_mask_custom_char(self):
        """Test masking with custom character."""
        options = ProtectionOptions(mask_char='X', visible_chars=4)
        masking = Masking(options)
        result = masking.protect("1234567890")
        assert result == "XXXXXX7890"

    def test_mask_short_value(self):
        """Test masking value shorter than visible chars."""
        options = ProtectionOptions(visible_chars=10)
        masking = Masking(options)
        result = masking.protect("short")
        assert result == "*****"

    def test_mask_empty_string(self, masking):
        """Test masking empty string."""
        result = masking.protect("")
        assert result == ""

    def test_is_not_reversible(self, masking):
        """Test masking is not reversible."""
        assert masking.is_reversible is False


class TestRedaction:
    """Tests for redaction protection."""

    def test_redact_value(self):
        """Test complete redaction."""
        redaction = Redaction()
        result = redaction.protect("sensitive data")
        assert result == "[REDACTED]"

    def test_custom_redaction_text(self):
        """Test custom redaction text."""
        redaction = Redaction(redaction_text="***REMOVED***")
        result = redaction.protect("sensitive")
        assert result == "***REMOVED***"

    def test_redact_empty_string(self):
        """Test redacting empty string."""
        redaction = Redaction()
        result = redaction.protect("")
        assert result == ""


class TestEmailMasking:
    """Tests for email-specific masking."""

    @pytest.fixture
    def masking(self):
        """Create email masking instance."""
        return EmailMasking()

    def test_mask_email(self, masking):
        """Test email masking preserves domain."""
        result = masking.protect("john.smith@example.com")
        assert "@example.com" in result
        assert "j" in result
        assert "h" in result

    def test_mask_short_local(self, masking):
        """Test masking short local part."""
        result = masking.protect("ab@test.com")
        assert result == "**@test.com"

    def test_mask_non_email(self, masking):
        """Test non-email falls back to default masking."""
        result = masking.protect("not an email")
        assert "@" not in result


class TestCreditCardMasking:
    """Tests for credit card masking."""

    @pytest.fixture
    def masking(self):
        """Create credit card masking instance."""
        return CreditCardMasking()

    def test_mask_card_number(self, masking):
        """Test credit card masking shows last 4."""
        result = masking.protect("4111111111111111")
        assert result.endswith("1111")
        assert result.count("*") == 12

    def test_mask_formatted_card(self, masking):
        """Test masking formatted card number."""
        result = masking.protect("4111-1111-1111-1111")
        assert result.endswith("1111")
        assert "-" in result


class TestPhoneMasking:
    """Tests for phone number masking."""

    @pytest.fixture
    def masking(self):
        """Create phone masking instance."""
        return PhoneMasking()

    def test_mask_phone(self, masking):
        """Test phone masking preserves format."""
        result = masking.protect("+44 7911 123456")
        assert result.endswith("3456")
        assert " " in result


class TestTokenization:
    """Tests for tokenization protection."""

    @pytest.fixture(autouse=True)
    def clear_vault(self):
        """Clear global vault before each test."""
        clear_global_vault()
        yield
        clear_global_vault()

    @pytest.fixture
    def tokenization(self):
        """Create tokenization instance."""
        return Tokenization()

    def test_tokenize_value(self, tokenization):
        """Test tokenization produces token."""
        result = tokenization.protect("sensitive@email.com")
        assert result.startswith("TOK_")
        assert len(result) > 4

    def test_tokenize_same_value_returns_same_token(self, tokenization):
        """Test same value gets same token."""
        token1 = tokenization.protect("test value")
        token2 = tokenization.protect("test value")
        assert token1 == token2

    def test_detokenize(self, tokenization):
        """Test detokenization returns original."""
        original = "sensitive data"
        token = tokenization.protect(original)
        result = tokenization.unprotect(token)
        assert result == original

    def test_is_reversible(self, tokenization):
        """Test tokenization is reversible."""
        assert tokenization.is_reversible is True

    def test_detokenize_unknown_token(self, tokenization):
        """Test detokenizing unknown token raises error."""
        with pytest.raises(ValueError):
            tokenization.unprotect("TOK_UNKNOWN123456")

    def test_custom_prefix(self):
        """Test custom token prefix."""
        tokenization = Tokenization(token_prefix="CUSTOM_")
        result = tokenization.protect("value")
        assert result.startswith("CUSTOM_")

    def test_deterministic_tokenization(self):
        """Test deterministic tokenization."""
        t1 = Tokenization(deterministic=True, vault=TokenVault())
        t2 = Tokenization(deterministic=True, vault=TokenVault())

        token1 = t1.protect("same value")
        token2 = t2.protect("same value")

        assert token1[4:] == token2[4:]


class TestUUIDTokenization:
    """Tests for UUID-based tokenization."""

    @pytest.fixture(autouse=True)
    def clear_vault(self):
        """Clear vault before each test."""
        clear_global_vault()
        yield

    def test_uuid_token_format(self):
        """Test UUID token format."""
        tokenization = UUIDTokenization()
        result = tokenization.protect("test")
        assert result.startswith("UUID_")
        assert len(result) == 5 + 32

    def test_uuid_detokenize(self):
        """Test UUID detokenization."""
        tokenization = UUIDTokenization()
        original = "sensitive"
        token = tokenization.protect(original)
        result = tokenization.unprotect(token)
        assert result == original


class TestFormatPreservingTokenization:
    """Tests for format-preserving tokenization."""

    @pytest.fixture
    def tokenization(self):
        """Create format-preserving tokenization."""
        return FormatPreservingTokenization(vault=TokenVault())

    def test_preserves_digit_format(self, tokenization):
        """Test digits are replaced with digits."""
        result = tokenization.protect("1234567890")
        assert result.isdigit()
        assert len(result) == 10

    def test_preserves_letter_format(self, tokenization):
        """Test letters are replaced with letters."""
        result = tokenization.protect("AbCdEf")
        assert result.isalpha()
        assert result[0].isupper()
        assert result[1].islower()

    def test_preserves_special_chars(self, tokenization):
        """Test special characters are preserved."""
        result = tokenization.protect("123-456-7890")
        assert "-" in result
        assert result.count("-") == 2


class TestTokenVault:
    """Tests for token vault."""

    @pytest.fixture
    def vault(self):
        """Create fresh vault."""
        return TokenVault()

    def test_store_and_retrieve(self, vault):
        """Test storing and retrieving."""
        vault.store("TOKEN123", "original value")
        assert vault.get_value("TOKEN123") == "original value"
        assert vault.get_token("original value") == "TOKEN123"

    def test_exists(self, vault):
        """Test existence check."""
        vault.store("TOKEN", "value")
        assert vault.exists("TOKEN") is True
        assert vault.exists("OTHER") is False

    def test_clear(self, vault):
        """Test clearing vault."""
        vault.store("T1", "V1")
        vault.store("T2", "V2")
        vault.clear()
        assert vault.size() == 0

    def test_size(self, vault):
        """Test size tracking."""
        assert vault.size() == 0
        vault.store("T1", "V1")
        assert vault.size() == 1
        vault.store("T2", "V2")
        assert vault.size() == 2
