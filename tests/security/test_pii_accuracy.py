"""Security tests for PII detection accuracy.

Measures precision, recall, and F1-score for PII detection.
"""

import pandas as pd
import pytest
from dataclasses import dataclass

from src.detection.presidio_detector import PresidioDetector, create_detector


@dataclass
class AccuracyMetrics:
    """Metrics for evaluating detection accuracy."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        """Calculate precision (TP / (TP + FP))."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom

    @property
    def recall(self) -> float:
        """Calculate recall (TP / (TP + FN))."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom

    @property
    def f1_score(self) -> float:
        """Calculate F1 score (harmonic mean of precision and recall)."""
        if self.precision + self.recall == 0:
            return 0.0
        num = 2 * (self.precision * self.recall)
        return num / (self.precision + self.recall)


@dataclass
class LabeledPII:
    """A labeled PII entity for testing."""

    text: str
    entity_type: str
    is_pii: bool = True


class TestEmailDetectionAccuracy:
    """Test email address detection accuracy."""

    @pytest.fixture
    def detector(self):
        """Create detector for email testing."""
        return PresidioDetector(
            entities=['EMAIL_ADDRESS'],
            score_threshold=0.5
        )

    @pytest.fixture
    def labeled_emails(self) -> list[LabeledPII]:
        """Labeled email test cases."""
        return [
            LabeledPII("john.smith@example.com", "EMAIL_ADDRESS", True),
            LabeledPII("jane_doe123@company.co.uk", "EMAIL_ADDRESS", True),
            LabeledPII("user+tag@subdomain.domain.org", "EMAIL_ADDRESS", True),
            LabeledPII("simple@test.com", "EMAIL_ADDRESS", True),
            LabeledPII("first.last@test.io", "EMAIL_ADDRESS", True),
            LabeledPII("admin@gov.uk", "EMAIL_ADDRESS", True),
            LabeledPII("info@cambridge.ac.uk", "EMAIL_ADDRESS", True),
            LabeledPII("hello.world@example.com", "EMAIL_ADDRESS", True),
            LabeledPII("a.b.c.d@example.io", "EMAIL_ADDRESS", True),
            LabeledPII("user-name@example.org", "EMAIL_ADDRESS", True),
            LabeledPII("contact@business.com", "EMAIL_ADDRESS", True),
            LabeledPII("alice@example.co", "EMAIL_ADDRESS", True),
            LabeledPII("bob42@example.net", "EMAIL_ADDRESS", True),
            LabeledPII("oliver.davies@nhs.uk", "EMAIL_ADDRESS", True),
            LabeledPII("emma_johnson@university.edu", "EMAIL_ADDRESS", True),
            LabeledPII("notanemail", "EMAIL_ADDRESS", False),
            LabeledPII("just plain text", "EMAIL_ADDRESS", False),
            LabeledPII("hello world", "EMAIL_ADDRESS", False),
            LabeledPII("12345", "EMAIL_ADDRESS", False),
            LabeledPII("normal sentence here", "EMAIL_ADDRESS", False),
            LabeledPII("nothing of interest", "EMAIL_ADDRESS", False),
            LabeledPII("a quick brown fox", "EMAIL_ADDRESS", False),
            LabeledPII("the lazy dog", "EMAIL_ADDRESS", False),
            LabeledPII("yesterday tomorrow", "EMAIL_ADDRESS", False),
            LabeledPII("morning afternoon", "EMAIL_ADDRESS", False),
            LabeledPII("page header text", "EMAIL_ADDRESS", False),
            LabeledPII("random words only", "EMAIL_ADDRESS", False),
            LabeledPII("simple description line", "EMAIL_ADDRESS", False),
            LabeledPII("title of section", "EMAIL_ADDRESS", False),
            LabeledPII("category label", "EMAIL_ADDRESS", False),
        ]

    @pytest.mark.security
    def test_email_detection_accuracy(self, detector, labeled_emails):
        """Test email detection meets accuracy threshold."""
        metrics = AccuracyMetrics()

        for labeled in labeled_emails:
            entities = detector.detect_text(labeled.text)
            detected = any(e.entity_type == 'EMAIL_ADDRESS' for e in entities)

            if labeled.is_pii and detected:
                metrics.true_positives += 1
            elif labeled.is_pii and not detected:
                metrics.false_negatives += 1
            elif not labeled.is_pii and detected:
                metrics.false_positives += 1

        prec = metrics.precision
        assert prec >= 0.85, f"Precision {prec:.2f} below 0.85"
        recall = metrics.recall
        assert recall >= 0.85, f"Recall {recall:.2f} below 0.85"
        f1 = metrics.f1_score
        assert f1 >= 0.9, f"F1 {f1:.2f} below 0.9"


class TestPhoneDetectionAccuracy:
    """Test phone number detection accuracy."""

    @pytest.fixture
    def detector(self):
        """Create detector for phone testing."""
        return create_detector(
            entities=['PHONE_NUMBER', 'UK_PHONE'],
            score_threshold=0.5
        )

    @pytest.fixture
    def labeled_phones(self) -> list[LabeledPII]:
        """Labeled phone test cases."""
        return [
            LabeledPII("+44 7911 123456", "PHONE_NUMBER", True),
            LabeledPII("07911 123456", "PHONE_NUMBER", True),
            LabeledPII("+1 555-123-4567", "PHONE_NUMBER", True),
            LabeledPII("020 7946 0958", "PHONE_NUMBER", True),
            LabeledPII("+44 20 7946 0958", "PHONE_NUMBER", True),
            LabeledPII("+44 7700 900123", "PHONE_NUMBER", True),
            LabeledPII("07700 900123", "PHONE_NUMBER", True),
            LabeledPII("+44 161 555 1234", "PHONE_NUMBER", True),
            LabeledPII("0161 555 1234", "PHONE_NUMBER", True),
            LabeledPII("+44 121 555 0987", "PHONE_NUMBER", True),
            LabeledPII("0121 555 0987", "PHONE_NUMBER", True),
            LabeledPII("+44 7401 234567", "PHONE_NUMBER", True),
            LabeledPII("07401 234567", "PHONE_NUMBER", True),
            LabeledPII("01632 960123", "PHONE_NUMBER", True),
            LabeledPII("+44 1632 960123", "PHONE_NUMBER", True),
            LabeledPII("12345", "PHONE_NUMBER", False),
            LabeledPII("not a phone", "PHONE_NUMBER", False),
            LabeledPII("abcdefghij", "PHONE_NUMBER", False),
            LabeledPII("hello world", "PHONE_NUMBER", False),
            LabeledPII("just text", "PHONE_NUMBER", False),
            LabeledPII("99", "PHONE_NUMBER", False),
            LabeledPII("the year 1999", "PHONE_NUMBER", False),
            LabeledPII("price was 1234", "PHONE_NUMBER", False),
            LabeledPII("room 101", "PHONE_NUMBER", False),
            LabeledPII("five", "PHONE_NUMBER", False),
            LabeledPII("ABC 123 XYZ", "PHONE_NUMBER", False),
            LabeledPII("address 10 Downing", "PHONE_NUMBER", False),
            LabeledPII("page 42", "PHONE_NUMBER", False),
            LabeledPII("section 7.3", "PHONE_NUMBER", False),
            LabeledPII("year 2024", "PHONE_NUMBER", False),
        ]

    @pytest.mark.security
    def test_phone_detection_accuracy(self, detector, labeled_phones):
        """Test phone detection meets accuracy threshold."""
        metrics = AccuracyMetrics()

        for labeled in labeled_phones:
            entities = detector.detect_text(labeled.text)
            detected = any(
                e.entity_type in ('PHONE_NUMBER', 'UK_PHONE')
                for e in entities
            )

            if labeled.is_pii and detected:
                metrics.true_positives += 1
            elif labeled.is_pii and not detected:
                metrics.false_negatives += 1
            elif not labeled.is_pii and detected:
                metrics.false_positives += 1

        f1 = metrics.f1_score
        assert f1 >= 0.9, f"F1 {f1:.2f} below 0.9"


class TestCreditCardDetectionAccuracy:
    """Test credit card detection accuracy."""

    @pytest.fixture
    def detector(self):
        """Create detector for credit card testing."""
        return PresidioDetector(
            entities=['CREDIT_CARD'],
            score_threshold=0.5
        )

    @pytest.fixture
    def labeled_cards(self) -> list[LabeledPII]:
        """Labeled credit card test cases (Luhn-valid positives)."""
        positives = [
            "4111111111111111", "4111-1111-1111-1111", "4012888888881881",
            "4012 8888 8888 1881", "4242424242424242",
            "5500000000000004", "5500 0000 0000 0004", "5105105105105100",
            "5555555555554444",
            "378282246310005", "3782 822463 10005", "371449635398431",
            "340000000000009",
            "6011111111111117", "6011-1111-1111-1117", "6011000990139424",
            "6011000000000004",
            "30569309025904", "3530111333300000", "3566002020360505",
        ]
        negatives = [
            "1234567890123456", "9999999999999999", "0000000000000000",
            "1234", "12-34-5678", "abcdefghijklmnop", "123",
            "99999999999999999", "phone: 555-1234", "date: 2024-01-15",
            "normal text", "random words here", "mixed 1234 letters",
            "no card present", "not a card", "order id 12345",
        ]
        return (
                [LabeledPII(v, "CREDIT_CARD", True) for v in positives]
                + [LabeledPII(v, "CREDIT_CARD", False) for v in negatives]
        )

    @pytest.mark.security
    def test_credit_card_detection_accuracy(self, detector, labeled_cards):
        """Test credit card detection meets accuracy threshold."""
        metrics = AccuracyMetrics()

        for labeled in labeled_cards:
            entities = detector.detect_text(labeled.text)
            detected = any(e.entity_type == 'CREDIT_CARD' for e in entities)

            if labeled.is_pii and detected:
                metrics.true_positives += 1
            elif labeled.is_pii and not detected:
                metrics.false_negatives += 1
            elif not labeled.is_pii and detected:
                metrics.false_positives += 1

        f1 = metrics.f1_score
        assert f1 >= 0.9, f"F1 {f1:.2f} below 0.9"


class TestDataFrameDetectionAccuracy:
    """Test detection accuracy on DataFrame with mixed PII."""

    @pytest.fixture
    def detector(self):
        """Create detector for DataFrame testing."""
        return create_detector(score_threshold=0.5)

    @pytest.fixture
    def labeled_dataframe(self) -> tuple[pd.DataFrame, dict]:
        """Create labeled DataFrame with known PII locations."""
        df = pd.DataFrame({
            'id': [str(i) for i in range(1, 16)],
            'name': [
                'John Smith', 'Jane Doe', 'Bob Wilson', 'Alice Brown',
                'Charlie Davis', 'Eve Carter', 'Frank Hill', 'Grace Lee',
                'Henry Ward', 'Ivy King', 'Jack Reed', 'Karen Cox',
                'Liam Foster', 'Mia Brooks', 'Noah Stone',
            ],
            'email': [
                'john@example.com', 'jane@test.org', 'bob@company.co.uk',
                'not-an-email', 'charlie@domain.com',
                'eve.carter@example.com', 'frank@business.co.uk',
                'plain text only', 'henry@nhs.uk', 'ivy.king@gov.uk',
                'jack.reed@example.io', 'karen@university.ac.uk',
                'random words', 'mia@business.com', 'noah@example.org',
            ],
            'phone': [
                '+44 7911 123456', '020 7946 0958', 'no phone',
                '+1 555-123-4567', '07700 900123',
                '+44 121 555 1234', '0161 555 9876', 'just text',
                '+44 7401 234567', '01632 960123',
                '+44 20 7946 0958', '07911 654321',
                'address line', '0121 555 0987', '+44 7700 900456',
            ],
            'notes': ['n/a'] * 15,
        })

        expected = {
            'email': {
                0: True, 1: True, 2: True, 3: False, 4: True,
                5: True, 6: True, 7: False, 8: True, 9: True,
                10: True, 11: True, 12: False, 13: True, 14: True,
            },
            'phone': {
                0: True, 1: True, 2: False, 3: True, 4: True,
                5: True, 6: True, 7: False, 8: True, 9: True,
                10: True, 11: True, 12: False, 13: True, 14: True,
            },
        }

        return df, expected

    @pytest.mark.security
    def test_dataframe_detection_accuracy(self, detector, labeled_dataframe):
        """Test DataFrame detection accuracy."""
        df, expected = labeled_dataframe
        metrics = {'email': AccuracyMetrics(), 'phone': AccuracyMetrics()}

        targets = {
            'email': {'EMAIL_ADDRESS'},
            'phone': {'PHONE_NUMBER', 'UK_PHONE'},
        }
        for column in ['email', 'phone']:
            result = detector.detect_column(df, column)

            rows_with_pii = set()
            for entity in result.entities:
                if entity.row_index is not None and entity.entity_type in targets[column]:
                    rows_with_pii.add(entity.row_index)

            for row_idx, has_pii in expected[column].items():
                detected = row_idx in rows_with_pii

                if has_pii and detected:
                    metrics[column].true_positives += 1
                elif has_pii and not detected:
                    metrics[column].false_negatives += 1
                elif not has_pii and detected:
                    metrics[column].false_positives += 1

        for column, m in metrics.items():
            assert m.f1_score >= 0.9, (
                f"{column} F1 {m.f1_score:.2f} below 0.9"
            )


class TestNoFalseNegativesOnCriticalPII:
    """Ensure no false negatives on critical PII types."""

    @pytest.fixture
    def detector(self):
        """Create detector with low threshold for critical PII."""
        return PresidioDetector(score_threshold=0.3)

    @pytest.mark.security
    def test_no_missed_credit_cards(self, detector):
        """Ensure valid credit card numbers are always detected."""
        critical_cards = [
            "4111111111111111",
            "5500000000000004",
            "340000000000009",
            "6011000000000004",
        ]

        for card in critical_cards:
            text = f"Payment card: {card}"
            entities = detector.detect_text(text)
            detected = any(e.entity_type == 'CREDIT_CARD' for e in entities)
            assert detected, f"Missed credit card: {card}"

    @pytest.mark.security
    def test_no_missed_emails_in_context(self, detector):
        """Ensure emails in context are detected."""
        test_cases = [
            "Please contact john@example.com for assistance",
            "Email: support@company.co.uk",
            "Send to: user.name@subdomain.domain.org",
        ]

        for text in test_cases:
            entities = detector.detect_text(text)
            detected = any(e.entity_type == 'EMAIL_ADDRESS' for e in entities)
            assert detected, f"Missed email in: {text}"


class TestDetectionConsistency:
    """Test detection consistency across multiple runs."""

    @pytest.fixture
    def detector(self):
        """Create detector for consistency testing."""
        return PresidioDetector(score_threshold=0.5)

    @pytest.mark.security
    def test_consistent_detection(self, detector):
        """Ensure detection is consistent across multiple runs."""
        text = "Contact john.smith@example.com or call +44 7911 123456"

        results = []
        for _ in range(5):
            entities = detector.detect_text(text)
            entity_types = sorted([e.entity_type for e in entities])
            results.append(tuple(entity_types))

        assert len(set(results)) == 1, "Detection results vary across runs"

    @pytest.mark.security
    def test_consistent_scores(self, detector):
        """Ensure confidence scores are consistent across runs."""
        text = "Email: test@example.com"

        scores = []
        for _ in range(5):
            entities = detector.detect_text(text)
            email_entities = [
                e for e in entities if e.entity_type == 'EMAIL_ADDRESS'
            ]
            assert email_entities, "EMAIL_ADDRESS not detected"
            scores.append(email_entities[0].score)

        assert max(scores) - min(scores) < 0.01, "Scores vary across runs"
