"""CSV file handler implementation."""

import csv
import io
from typing import Optional

import pandas as pd
from src.handlers.base_handler import BaseHandler


class CSVHandler(BaseHandler):
    """Handler for CSV file format processing."""

    SUPPORTED_EXTENSIONS = ['.csv']

    def __init__(self, delimiter: str = ',', encoding: str = 'utf-8') -> None:
        super().__init__()
        self._delimiter = delimiter
        self._encoding = encoding
        self._detected_delimiter: Optional[str] = None

    @property
    def delimiter(self) -> str:
        """Get the delimiter used for parsing."""
        return self._detected_delimiter or self._delimiter

    def validate(self, content: bytes, file_name: str) -> bool:
        """Validate CSV content.

        Checks:
        - File is not empty
        - Content is valid UTF-8
        - Has consistent column count
        - Has at least header row

        Args:
            content: Raw CSV bytes
            file_name: Original file name

        Returns:
            True if valid CSV
        """
        if not content or len(content.strip()) == 0:
            self._add_validation_error("File is empty")
            return False

        try:
            text = content.decode(self._encoding)
        except UnicodeDecodeError as e:
            self._add_validation_error(f"Invalid encoding: {e}")
            return False

        try:
            self._detected_delimiter = self._detect_delimiter(text)
        except Exception as e:
            self._add_validation_error(f"Failed to detect delimiter: {e}")
            return False

        lines = [line for line in text.strip().split('\n') if line.strip()]
        if len(lines) < 1:
            self._add_validation_error("No data rows found")
            return False

        try:
            text_io = io.StringIO(text)
            reader = csv.reader(text_io, delimiter=self._detected_delimiter)
            rows = list(reader)

            if len(rows) < 1:
                self._add_validation_error("No rows found in CSV")
                return False

            header_count = len(rows[0])
            if header_count == 0:
                self._add_validation_error("No columns found in header")
                return False

            for i, row in enumerate(rows[1:], start=2):
                if len(row) != header_count:
                    msg = (
                        f"Row {i} has {len(row)} columns, "
                        f"expected {header_count}"
                    )
                    self._add_validation_error(msg)
                    return False

        except csv.Error as e:
            self._add_validation_error(f"CSV parsing error: {e}")
            return False

        return True

    def parse(self, content: bytes) -> pd.DataFrame:
        """Parse CSV content into DataFrame.

        Args:
            content: Raw CSV bytes

        Returns:
            Parsed DataFrame
        """
        text = content.decode(self._encoding)
        delimiter = self._detected_delimiter or self._detect_delimiter(text)

        df = pd.read_csv(
            io.StringIO(text),
            delimiter=delimiter,
            dtype=str,
            keep_default_na=False
        )

        df.columns = df.columns.str.strip()

        return df

    def serialize(self, df: pd.DataFrame) -> bytes:
        """Serialize DataFrame to CSV bytes.

        Args:
            df: DataFrame to serialize

        Returns:
            CSV bytes
        """
        buffer = io.StringIO()
        df.to_csv(buffer, index=False, quoting=csv.QUOTE_MINIMAL)
        return buffer.getvalue().encode(self._encoding)

    def get_content_type(self) -> str:
        """Get MIME content type for CSV."""
        return 'text/csv'

    def _get_format_name(self) -> str:
        """Get format name."""
        return 'CSV'

    def _detect_delimiter(self, text: str) -> str:
        """Detect CSV delimiter from content.

        Uses csv.Sniffer to detect the delimiter.

        Args:
            text: CSV text content

        Returns:
            Detected delimiter character
        """
        sample = text[:8192]

        try:
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(sample, delimiters=',;\t|')
            return dialect.delimiter
        except csv.Error:
            return self._delimiter
