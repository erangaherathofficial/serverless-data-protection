"""PII detection using Microsoft Presidio."""

import logging
from dataclasses import dataclass, field
from typing import Optional

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

logger = logging.getLogger(__name__)


@dataclass
class PIIEntity:
    """Represents a detected PII entity."""

    entity_type: str
    text: str
    start: int
    end: int
    score: float
    column_name: Optional[str] = None
    row_index: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'entity_type': self.entity_type,
            'text': self.text,
            'start': self.start,
            'end': self.end,
            'score': self.score,
            'column_name': self.column_name,
            'row_index': self.row_index
        }


@dataclass
class DetectionResult:
    """Result of PII detection on a dataset."""

    entities: list[PIIEntity] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    columns_with_pii: set[str] = field(default_factory=set)
    total_cells_scanned: int = 0
    cells_with_pii: int = 0

    def add_entity(self, entity: PIIEntity) -> None:
        """Add detected entity and update counts."""
        self.entities.append(entity)
        self.entity_counts[entity.entity_type] = (
            self.entity_counts.get(entity.entity_type, 0) + 1
        )
        if entity.column_name:
            self.columns_with_pii.add(entity.column_name)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'entities': [e.to_dict() for e in self.entities],
            'entity_counts': self.entity_counts,
            'columns_with_pii': list(self.columns_with_pii),
            'total_cells_scanned': self.total_cells_scanned,
            'cells_with_pii': self.cells_with_pii
        }


class PresidioDetector:
    """PII detector using Microsoft Presidio Analyzer.

    Detects various PII entity types in text data including:
    - EMAIL_ADDRESS
    - PHONE_NUMBER
    - CREDIT_CARD
    - PERSON
    - LOCATION
    - DATE_TIME
    - IP_ADDRESS
    - IBAN_CODE
    - UK_NHS (custom)
    """

    DEFAULT_ENTITIES = [
        'EMAIL_ADDRESS',
        'PHONE_NUMBER',
        'CREDIT_CARD',
        'PERSON',
        'LOCATION',
        'DATE_TIME',
        'IP_ADDRESS',
        'IBAN_CODE',
        'US_SSN',
        'UK_NHS',
    ]

    def __init__(
        self,
        entities: Optional[list[str]] = None,
        score_threshold: float = 0.7,
        language: str = 'en'
    ) -> None:
        """Initialize Presidio detector.

        Args:
            entities: List of entity types to detect (default: all supported)
            score_threshold: Minimum confidence score (0.0 to 1.0)
            language: Language code for NLP processing
        """
        self._entities = entities or self.DEFAULT_ENTITIES
        self._score_threshold = score_threshold
        self._language = language
        self._analyzer: Optional[AnalyzerEngine] = None
        self._custom_recognizers: list = []

    @property
    def analyzer(self) -> AnalyzerEngine:
        """Get or create analyzer engine (lazy initialization)."""
        if self._analyzer is None:
            self._analyzer = self._create_analyzer()
        return self._analyzer

    def _create_analyzer(self) -> AnalyzerEngine:
        """Create and configure Presidio analyzer engine."""
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            })
            nlp_engine = provider.create_engine()

            analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[self._language]
            )
        except Exception as e:
            logger.warning(f"Failed to create NLP engine: {e}. Using default.")
            analyzer = AnalyzerEngine()

        for recognizer in self._custom_recognizers:
            analyzer.registry.add_recognizer(recognizer)

        return analyzer

    def add_custom_recognizer(self, recognizer) -> None:
        """Add custom recognizer to the analyzer.

        Args:
            recognizer: Presidio recognizer instance
        """
        self._custom_recognizers.append(recognizer)
        if self._analyzer is not None:
            self._analyzer.registry.add_recognizer(recognizer)

    def detect_text(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text.

        Args:
            text: Text to analyze

        Returns:
            List of detected PII entities
        """
        if not text or not text.strip():
            return []

        try:
            results = self.analyzer.analyze(
                text=text,
                entities=self._entities,
                language=self._language,
                score_threshold=self._score_threshold
            )
        except Exception as e:
            logger.error(f"Presidio analysis failed: {e}")
            return []

        return [
            PIIEntity(
                entity_type=result.entity_type,
                text=text[result.start:result.end],
                start=result.start,
                end=result.end,
                score=result.score
            )
            for result in results
        ]

    def detect_dataframe(self, df, columns: Optional[list[str]] = None) -> DetectionResult:
        """Detect PII entities in DataFrame.

        Args:
            df: Pandas DataFrame to analyze
            columns: Specific columns to scan (default: all string columns)

        Returns:
            DetectionResult with all detected entities
        """
        result = DetectionResult()

        if columns is None:
            columns = [
                col for col in df.columns
                if df[col].dtype == 'object' or str(df[col].dtype) == 'string'
            ]

        for col in columns:
            if col not in df.columns:
                continue

            for row_idx, value in enumerate(df[col]):
                result.total_cells_scanned += 1

                if not isinstance(value, str) or not value.strip():
                    continue

                entities = self.detect_text(str(value))

                if entities:
                    result.cells_with_pii += 1

                    for entity in entities:
                        entity.column_name = col
                        entity.row_index = row_idx
                        result.add_entity(entity)

        return result

    def detect_column(self, df, column_name: str) -> DetectionResult:
        """Detect PII entities in a specific column.

        Args:
            df: Pandas DataFrame
            column_name: Column to analyze

        Returns:
            DetectionResult for the column
        """
        return self.detect_dataframe(df, columns=[column_name])

    def get_column_entity_types(self, df, column_name: str) -> set[str]:
        """Get unique entity types found in a column.

        Args:
            df: Pandas DataFrame
            column_name: Column to analyze

        Returns:
            Set of entity type names found
        """
        result = self.detect_column(df, column_name)
        return set(result.entity_counts.keys())

    def get_pii_summary(self, df) -> dict[str, dict[str, int]]:
        """Get summary of PII entities by column.

        Args:
            df: Pandas DataFrame

        Returns:
            Dictionary mapping column names to entity type counts
        """
        summary = {}
        result = self.detect_dataframe(df)

        for entity in result.entities:
            if entity.column_name:
                if entity.column_name not in summary:
                    summary[entity.column_name] = {}
                summary[entity.column_name][entity.entity_type] = (
                    summary[entity.column_name].get(entity.entity_type, 0) + 1
                )

        return summary

    @property
    def supported_entities(self) -> list[str]:
        """Get list of supported entity types."""
        return self._entities.copy()

    @property
    def score_threshold(self) -> float:
        """Get current score threshold."""
        return self._score_threshold

    def set_score_threshold(self, threshold: float) -> None:
        """Update score threshold.

        Args:
            threshold: New threshold (0.0 to 1.0)
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self._score_threshold = threshold


def create_detector(
    entities: Optional[list[str]] = None,
    score_threshold: float = 0.7,
    include_custom: bool = True
) -> PresidioDetector:
    """Create configured Presidio detector.

    Args:
        entities: Entity types to detect
        score_threshold: Minimum confidence score
        include_custom: Whether to include custom recognizers

    Returns:
        Configured PresidioDetector instance
    """
    from src.detection.custom_recognizers import get_custom_recognizers

    detector = PresidioDetector(
        entities=entities,
        score_threshold=score_threshold
    )

    if include_custom:
        for recognizer in get_custom_recognizers():
            detector.add_custom_recognizer(recognizer)

    return detector
