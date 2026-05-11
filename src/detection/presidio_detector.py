"""PII detection using Microsoft Presidio."""

from dataclasses import asdict, dataclass, field
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from typing import Optional

from src.detection.custom_recognizers import get_custom_recognizers


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
        return asdict(self)


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
        d = asdict(self)
        d['columns_with_pii'] = list(d['columns_with_pii'])
        return d


class PresidioDetector:
    """PII detector using Microsoft Presidio Analyzer.

    Detects PII entity types listed in DEFAULT_ENTITIES, covering Presidio's
    built-in recognisers (EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, PERSON,
    LOCATION, DATE_TIME, IP_ADDRESS, IBAN_CODE) and the framework's UK custom
    recognisers (UK_NHS, UK_NINO, UK_POSTCODE, UK_PHONE, UK_CITY, UK_NAME,
    UK_DRIVERS_LICENSE, UK_PASSPORT, UK_BANK_ACCOUNT, UK_VRN).
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
        'UK_NHS',
        'UK_NINO',
        'UK_POSTCODE',
        'UK_PHONE',
        'UK_CITY',
        'UK_NAME',
        'UK_DRIVERS_LICENSE',
        'UK_PASSPORT',
        'UK_BANK_ACCOUNT',
        'UK_VRN',
    ]

    def __init__(
            self,
            entities: Optional[list[str]] = None,
            score_threshold: float = 0.7,
            language: str = 'en',
            custom_recognizers: Optional[list] = None,
    ) -> None:
        """Initialize Presidio detector.

        Args:
            entities: List of entity types to detect (default: all supported)
            score_threshold: Minimum confidence score (0.0 to 1.0)
            language: Language code for NLP processing
            custom_recognizers: Recognizers to register with the analyzer
        """
        self._entities = entities or self.DEFAULT_ENTITIES
        self._score_threshold = score_threshold
        self._language = language
        self._custom_recognizers = custom_recognizers or []
        self._analyzer: Optional[AnalyzerEngine] = None

    @property
    def analyzer(self) -> AnalyzerEngine:
        """Get or create analyzer engine (lazy initialization)."""
        if self._analyzer is None:
            self._analyzer = self._create_analyzer()
        return self._analyzer

    def _create_analyzer(self) -> AnalyzerEngine:
        """Create and configure Presidio analyzer engine.

        Fails loudly if the configured spaCy model cannot be loaded — falling
        back to a smaller default would silently degrade detection accuracy
        and hide a deployment problem.
        """
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
        })
        nlp_engine = provider.create_engine()

        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=[self._language]
        )

        for recognizer in self._custom_recognizers:
            analyzer.registry.add_recognizer(recognizer)

        return analyzer

    def detect_text(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text.

        Args:
            text: Text to analyze

        Returns:
            List of detected PII entities
        """
        if not text or not text.strip():
            return []

        results = self.analyzer.analyze(
            text=text,
            entities=self._entities,
            language=self._language,
            score_threshold=self._score_threshold
        )

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

    def detect_dataframe(
            self, df, columns: Optional[list[str]] = None
    ) -> DetectionResult:
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
                if (dtype := str(df[col].dtype)) == 'object'
                   or dtype.startswith('string')
            ]

        for col in columns:
            if col not in df.columns:
                continue

            for row_idx, value in enumerate(df[col]):
                result.total_cells_scanned += 1

                if not isinstance(value, str) or not value.strip():
                    continue

                entities = self.detect_text(value)

                if entities:
                    result.cells_with_pii += 1

                    for entity in entities:
                        entity.column_name = col
                        entity.row_index = row_idx
                        result.add_entity(entity)

        return result

    def detect_column(self, df, column_name: str) -> DetectionResult:
        """Detect PII entities in a single named column."""
        return self.detect_dataframe(df, columns=[column_name])


def create_detector(
        entities: Optional[list[str]] = None,
        score_threshold: float = 0.7,
) -> PresidioDetector:
    """Create a Presidio detector with the framework's UK custom recognizers."""
    return PresidioDetector(
        entities=entities,
        score_threshold=score_threshold,
        custom_recognizers=get_custom_recognizers(),
    )
