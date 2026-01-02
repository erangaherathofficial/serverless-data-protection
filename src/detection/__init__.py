"""PII detection package."""

from src.detection.custom_recognizers import (
    BankAccountRecognizer,
    DriversLicenseRecognizer,
    PassportRecognizer,
    UKNHSRecognizer,
    UKNINORecognizer,
    UKPhoneRecognizer,
    UKPostcodeRecognizer,
    VehicleRegistrationRecognizer,
    get_custom_recognizers,
    get_uk_recognizers,
)
from src.detection.presidio_detector import (
    DetectionResult,
    PIIEntity,
    PresidioDetector,
    create_detector,
)

__all__ = [
    'PresidioDetector',
    'PIIEntity',
    'DetectionResult',
    'create_detector',
    'UKNHSRecognizer',
    'UKNINORecognizer',
    'UKPostcodeRecognizer',
    'UKPhoneRecognizer',
    'DriversLicenseRecognizer',
    'PassportRecognizer',
    'BankAccountRecognizer',
    'VehicleRegistrationRecognizer',
    'get_custom_recognizers',
    'get_uk_recognizers',
]
