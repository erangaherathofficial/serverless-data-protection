"""Unit tests for PII detection module."""

import pandas as pd
import pytest

from src.detection.custom_recognizers import (
    UKNHSRecognizer,
    UKNINORecognizer,
    UKPhoneRecognizer,
    UKPostcodeRecognizer,
    get_custom_recognizers,
)
from src.detection.presidio_detector import (
    DetectionResult,
    PIIEntity,
    PresidioDetector,
)


class TestPIIEntity:
    """Tests for PIIEntity dataclass."""

    def test_entity_creation(self):
        """Test PIIEntity creation."""
        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@example.com',
            start=0,
            end=16,
            score=0.95,
            column_name='email',
            row_index=0
        )
        assert entity.entity_type == 'EMAIL_ADDRESS'
        assert entity.score == 0.95

    def test_entity_to_dict(self):
        """Test PIIEntity serialization."""
        entity = PIIEntity(
            entity_type='PHONE_NUMBER',
            text='+44 7911 123456',
            start=0,
            end=15,
            score=0.9
        )
        result = entity.to_dict()
        assert result['entity_type'] == 'PHONE_NUMBER'
        assert result['text'] == '+44 7911 123456'


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_empty_result(self):
        """Test empty detection result."""
        result = DetectionResult()
        assert len(result.entities) == 0
        assert result.total_cells_scanned == 0

    def test_add_entity(self):
        """Test adding entities to result."""
        result = DetectionResult()
        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0,
            end=13,
            score=0.95,
            column_name='email'
        )
        result.add_entity(entity)

        assert len(result.entities) == 1
        assert result.entity_counts['EMAIL_ADDRESS'] == 1
        assert 'email' in result.columns_with_pii

    def test_to_dict(self):
        """Test result serialization."""
        result = DetectionResult()
        result.total_cells_scanned = 100
        result.cells_with_pii = 10

        data = result.to_dict()
        assert data['total_cells_scanned'] == 100
        assert data['cells_with_pii'] == 10


class TestPresidioDetector:
    """Tests for PresidioDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return PresidioDetector(score_threshold=0.5)

    def test_detect_email(self, detector):
        """Test email detection."""
        text = "Contact me at john.smith@example.com for more info."
        entities = detector.detect_text(text)

        email_entities = [
            e for e in entities if e.entity_type == 'EMAIL_ADDRESS'
        ]
        assert len(email_entities) >= 1
        assert 'john.smith@example.com' in email_entities[0].text

    def test_detect_credit_card(self, detector):
        """Test credit card detection."""
        text = "My card number is 4111-1111-1111-1111."
        entities = detector.detect_text(text)

        card_entities = [e for e in entities if e.entity_type == 'CREDIT_CARD']
        assert len(card_entities) >= 1

    def test_detect_empty_text(self, detector):
        """Test detection on empty text."""
        entities = detector.detect_text("")
        assert len(entities) == 0

        entities = detector.detect_text("   ")
        assert len(entities) == 0

    def test_detect_no_pii(self, detector):
        """Test detection on text without PII."""
        text = "The cat sat on the mat."
        entities = detector.detect_text(text)
        # Filter out low-confidence detections that may be false positives
        high_confidence = [e for e in entities if e.score >= 0.7]
        assert len(high_confidence) == 0

    def test_detect_dataframe(self, detector):
        """Test detection on DataFrame."""
        df = pd.DataFrame({
            'name': ['John Smith', 'Jane Doe'],
            'email': ['john@test.com', 'jane@test.com'],
            'notes': ['Regular customer', 'VIP customer']
        })

        result = detector.detect_dataframe(df)

        assert result.total_cells_scanned == 6
        assert result.cells_with_pii > 0
        assert 'email' in result.columns_with_pii

    def test_detect_column(self, detector):
        """Test detection on specific column."""
        df = pd.DataFrame({
            'email': ['test1@example.com', 'test2@example.com'],
            'name': ['John', 'Jane']
        })

        result = detector.detect_column(df, 'email')

        assert result.total_cells_scanned == 2
        assert 'EMAIL_ADDRESS' in result.entity_counts


class TestUKNHSRecognizer:
    """Tests for UK NHS number recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return UKNHSRecognizer()

    def test_valid_nhs_number_spaced(self, recognizer):
        """Test valid NHS number with spaces."""
        valid = recognizer.validate_result("943 476 5919")
        assert valid is True

    def test_valid_nhs_number_continuous(self, recognizer):
        """Test valid NHS number without spaces."""
        valid = recognizer.validate_result("9434765919")
        assert valid is True

    def test_invalid_nhs_number_wrong_length(self, recognizer):
        """Test invalid NHS number with wrong length."""
        valid = recognizer.validate_result("12345")
        assert valid is False

    def test_invalid_nhs_number_bad_checksum(self, recognizer):
        """Test invalid NHS number with wrong check digit."""
        valid = recognizer.validate_result("1234567890")
        assert valid is False


class TestUKNINORecognizer:
    """Tests for UK National Insurance Number recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return UKNINORecognizer()

    def test_valid_nino(self, recognizer):
        """Test valid NINO format."""
        valid = recognizer.validate_result("AB123456C")
        assert valid is True

    def test_invalid_nino_prefix(self, recognizer):
        """Test invalid NINO with disallowed prefix."""
        valid = recognizer.validate_result("BG123456C")
        assert valid is False

    def test_invalid_nino_length(self, recognizer):
        """Test invalid NINO with wrong length."""
        valid = recognizer.validate_result("AB12345C")
        assert valid is False


class TestUKPhoneRecognizer:
    """Tests for UK phone number recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return UKPhoneRecognizer()

    def test_patterns_exist(self, recognizer):
        """Test recognizer has patterns defined."""
        assert len(recognizer.patterns) > 0

    def test_supported_entity(self, recognizer):
        """Test correct entity type."""
        assert recognizer.supported_entities == ['UK_PHONE']


class TestUKPostcodeRecognizer:
    """Tests for UK postcode recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return UKPostcodeRecognizer()

    def test_patterns_exist(self, recognizer):
        """Test recognizer has patterns defined."""
        assert len(recognizer.patterns) > 0

    def test_supported_entity(self, recognizer):
        """Test correct entity type."""
        assert recognizer.supported_entities == ['UK_POSTCODE']


class TestCustomRecognizers:
    """Tests for custom recognizer collection."""

    def test_get_custom_recognizers(self):
        """Test getting all custom recognizers."""
        recognizers = get_custom_recognizers()
        assert len(recognizers) == 10

    def test_recognizer_types(self):
        """Test recognizer entity types are unique."""
        recognizers = get_custom_recognizers()
        entity_types = [r.supported_entities[0] for r in recognizers]
        assert len(entity_types) == len(set(entity_types))
