"""Custom PII recognizers for Presidio."""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer


class UKNHSRecognizer(PatternRecognizer):
    """Recognizer for UK NHS (National Health Service) numbers.

    NHS numbers are 10-digit numbers with a check digit.
    Format: XXX XXX XXXX or XXXXXXXXXX
    """

    PATTERNS = [
        Pattern(
            name='uk_nhs_spaced',
            regex=r'\b\d{3}\s\d{3}\s\d{4}\b',
            score=0.85
        ),
        Pattern(
            name='uk_nhs_continuous',
            regex=r'\b\d{10}\b',
            score=0.6
        ),
    ]

    CONTEXT_WORDS = [
        'nhs', 'national health', 'health service',
        'patient', 'hospital', 'medical', 'healthcare'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_NHS',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Validate NHS number using check digit algorithm."""
        digits = re.sub(r'\D', '', pattern_text)

        if len(digits) != 10:
            return False

        weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        total = sum(int(d) * w for d, w in zip(digits[:9], weights))
        remainder = total % 11
        check_digit = 11 - remainder

        if check_digit == 11:
            check_digit = 0

        if check_digit == 10:
            return False

        return int(digits[9]) == check_digit


class UKNINORecognizer(PatternRecognizer):
    """Recognizer for UK National Insurance Numbers.

    Format: AB123456C (two letters, six digits, one letter)
    """

    PATTERNS = [
        Pattern(
            name='uk_nino_spaced',
            regex=r'\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b',
            score=0.85
        ),
    ]

    CONTEXT_WORDS = [
        'national insurance', 'ni number', 'nino',
        'insurance number', 'tax', 'hmrc', 'employer'
    ]

    INVALID_PREFIXES = [
        'BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ',
        'DA', 'FA', 'IA', 'QA', 'OA'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_NINO',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Validate NINO format."""
        cleaned = pattern_text.upper().replace(' ', '')

        if len(cleaned) != 9:
            return False

        prefix = cleaned[:2]
        if prefix in self.INVALID_PREFIXES:
            return False

        if prefix[0] in 'DFIQUVO' or prefix[1] in 'DFIQUVO':
            return False

        return True


class UKPostcodeRecognizer(PatternRecognizer):
    """Recognizer for UK postcodes.

    Formats: A1 1AA, A11 1AA, AA1 1AA, AA11 1AA, A1A 1AA, AA1A 1AA
    """

    PATTERNS = [
        Pattern(
            name='uk_postcode',
            regex=r'\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b',
            score=0.7
        ),
    ]

    CONTEXT_WORDS = [
        'postcode', 'post code', 'address', 'zip',
        'location', 'delivery', 'shipping'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_POSTCODE',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


class UKPhoneRecognizer(PatternRecognizer):
    """Recognizer for UK phone numbers.

    Formats: +44, 07xxx, 01xxx, 02xxx, etc.
    """

    PATTERNS = [
        Pattern(
            name='uk_phone_international',
            regex=r'\+44\s?\d{4}\s?\d{6}',
            score=0.9
        ),
        Pattern(
            name='uk_phone_mobile',
            regex=r'\b07\d{3}\s?\d{6}\b',
            score=0.85
        ),
        Pattern(
            name='uk_phone_landline',
            regex=r'\b0[1-9]\d{2,4}\s?\d{5,6}\b',
            score=0.75
        ),
        Pattern(
            name='uk_phone_spaced',
            regex=r'\b0\d{2,4}\s\d{3}\s\d{4}\b',
            score=0.8
        ),
    ]

    CONTEXT_WORDS = [
        'phone', 'mobile', 'telephone', 'tel', 'call',
        'contact', 'number', 'cell'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_PHONE',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


class DriversLicenseRecognizer(PatternRecognizer):
    """Recognizer for UK Driving License numbers.

    Format: AAAAA NNNNN NNXXX (5 letters, 6 digits, 3 alphanumeric)
    """

    PATTERNS = [
        Pattern(
            name='uk_drivers_license',
            regex=r'\b[A-Z]{5}\d{6}[A-Z\d]{5}\b',
            score=0.8
        ),
        Pattern(
            name='uk_drivers_license_spaced',
            regex=r'\b[A-Z]{5}\s?\d{6}\s?[A-Z\d]{5}\b',
            score=0.75
        ),
    ]

    CONTEXT_WORDS = [
        'driving', 'license', 'licence', 'driver',
        'dvla', 'permit'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_DRIVERS_LICENSE',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


class PassportRecognizer(PatternRecognizer):
    """Recognizer for UK passport numbers.

    Format: 9 digits
    """

    PATTERNS = [
        Pattern(
            name='uk_passport',
            regex=r'\b\d{9}\b',
            score=0.5
        ),
    ]

    CONTEXT_WORDS = [
        'passport', 'travel', 'document', 'hmpo',
        'border', 'visa', 'immigration'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_PASSPORT',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


class BankAccountRecognizer(PatternRecognizer):
    """Recognizer for UK bank account numbers and sort codes.

    Account: 8 digits
    Sort code: XX-XX-XX
    """

    PATTERNS = [
        Pattern(
            name='uk_sort_code',
            regex=r'\b\d{2}-\d{2}-\d{2}\b',
            score=0.8
        ),
        Pattern(
            name='uk_account_number',
            regex=r'\b\d{8}\b',
            score=0.4
        ),
        Pattern(
            name='uk_sort_code_nospace',
            regex=r'\b\d{6}\b',
            score=0.3
        ),
    ]

    CONTEXT_WORDS = [
        'account', 'bank', 'sort code', 'account number',
        'payment', 'transfer', 'bacs', 'direct debit'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_BANK_ACCOUNT',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


class VehicleRegistrationRecognizer(PatternRecognizer):
    """Recognizer for UK vehicle registration plates.

    New format: AB12 CDE
    Old format: A123 BCD
    """

    PATTERNS = [
        Pattern(
            name='uk_vrn_new',
            regex=r'\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b',
            score=0.8
        ),
        Pattern(
            name='uk_vrn_old',
            regex=r'\b[A-Z]\d{1,3}\s?[A-Z]{3}\b',
            score=0.7
        ),
    ]

    CONTEXT_WORDS = [
        'vehicle', 'registration', 'car', 'plate',
        'dvla', 'number plate', 'license plate'
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity='UK_VRN',
            patterns=self.PATTERNS,
            context=self.CONTEXT_WORDS,
            supported_language='en'
        )


def get_custom_recognizers() -> list:
    """Get all custom recognizers.

    Returns:
        List of custom recognizer instances
    """
    return [
        UKNHSRecognizer(),
        UKNINORecognizer(),
        UKPostcodeRecognizer(),
        UKPhoneRecognizer(),
        DriversLicenseRecognizer(),
        PassportRecognizer(),
        BankAccountRecognizer(),
        VehicleRegistrationRecognizer(),
    ]
