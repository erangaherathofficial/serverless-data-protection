"""Abstract base handler for file processing."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd


@dataclass
class FileMetadata:
    """Metadata about a processed file."""

    file_name: str
    file_format: str
    size_bytes: int
    row_count: int = 0
    column_count: int = 0
    columns: list[str] = field(default_factory=list)
    schema: dict[str, str] = field(default_factory=dict)


@dataclass
class ProcessedData:
    """Container for processed file data."""

    dataframe: pd.DataFrame
    metadata: FileMetadata
    raw_content: Optional[bytes] = None


class BaseHandler(ABC):
    """Abstract base class for file format handlers.

    Implements the Template Method pattern for file processing,
    with concrete implementations for CSV, JSON, and Parquet formats.
    """

    SUPPORTED_EXTENSIONS: list[str] = []

    def __init__(self) -> None:
        self._validation_errors: list[str] = []

    @property
    def validation_errors(self) -> list[str]:
        """Get validation errors from last operation."""
        return self._validation_errors.copy()

    def process(self, content: bytes, file_name: str) -> ProcessedData:
        """Process file content and return structured data.

        Template method that orchestrates the processing pipeline.

        Args:
            content: Raw file bytes
            file_name: Original file name

        Returns:
            ProcessedData containing DataFrame and metadata

        Raises:
            ValueError: If file validation fails
        """
        self._validation_errors = []

        if not self.validate(content, file_name):
            raise ValueError(
                f"File validation failed: {'; '.join(self._validation_errors)}"
            )

        df = self.parse(content)
        metadata = self._extract_metadata(df, content, file_name)

        return ProcessedData(
            dataframe=df,
            metadata=metadata,
            raw_content=content
        )

    @abstractmethod
    def validate(self, content: bytes, file_name: str) -> bool:
        """Validate file content and format.

        Args:
            content: Raw file bytes
            file_name: Original file name

        Returns:
            True if valid, False otherwise
        """
        pass

    @abstractmethod
    def parse(self, content: bytes) -> pd.DataFrame:
        """Parse file content into DataFrame.

        Args:
            content: Raw file bytes

        Returns:
            Parsed DataFrame
        """
        pass

    @abstractmethod
    def serialize(self, df: pd.DataFrame) -> bytes:
        """Serialize DataFrame back to file format.

        Args:
            df: DataFrame to serialize

        Returns:
            Serialized bytes
        """
        pass

    @abstractmethod
    def get_content_type(self) -> str:
        """Get MIME content type for this format."""
        pass

    def _extract_metadata(self, df: pd.DataFrame, content: bytes,
                          file_name: str) -> FileMetadata:
        """Extract metadata from parsed DataFrame.

        Args:
            df: Parsed DataFrame
            content: Original file bytes
            file_name: Original file name

        Returns:
            FileMetadata object
        """
        schema = {col: str(dtype) for col, dtype in df.dtypes.items()}

        return FileMetadata(
            file_name=file_name,
            file_format=self._get_format_name(),
            size_bytes=len(content),
            row_count=len(df),
            column_count=len(df.columns),
            columns=list(df.columns),
            schema=schema
        )

    @abstractmethod
    def _get_format_name(self) -> str:
        """Get human-readable format name."""
        pass

    def _add_validation_error(self, error: str) -> None:
        """Add a validation error message."""
        self._validation_errors.append(error)

    @classmethod
    def supports_extension(cls, extension: str) -> bool:
        """Check if handler supports given file extension.

        Args:
            extension: File extension (with or without dot)

        Returns:
            True if supported
        """
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = f'.{ext}'
        return ext in cls.SUPPORTED_EXTENSIONS
