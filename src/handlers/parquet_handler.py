"""Parquet file handler implementation."""

import io
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from typing import Optional

from src.handlers.base_handler import BaseHandler, FileMetadata


class ParquetHandler(BaseHandler):
    """Handler for Parquet file format processing.

    Uses PyArrow for efficient Parquet reading/writing with
    schema preservation capabilities.
    """

    def __init__(self, compression: str = 'snappy') -> None:
        super().__init__()
        self._compression = compression
        self._original_schema: Optional[pa.Schema] = None

    @property
    def original_schema(self) -> Optional[pa.Schema]:
        """Get original Parquet schema."""
        return self._original_schema

    def validate(self, content: bytes, file_name: str) -> bool:
        """Validate Parquet content.

        Checks:
        - File is not empty
        - Content is valid Parquet format
        - Has readable schema

        Args:
            content: Raw Parquet bytes
            file_name: Original file name

        Returns:
            True if valid Parquet
        """
        if not content:
            self._add_validation_error("File is empty")
            return False

        if len(content) < 4:
            self._add_validation_error("File too small to be valid Parquet")
            return False

        if content[:4] != b'PAR1':
            msg = "Invalid Parquet magic bytes (missing PAR1 header)"
            self._add_validation_error(msg)
            return False

        if content[-4:] != b'PAR1':
            msg = "Invalid Parquet magic bytes (missing PAR1 footer)"
            self._add_validation_error(msg)
            return False

        try:
            buffer = io.BytesIO(content)
            parquet_file = pq.ParquetFile(buffer)

            self._original_schema = parquet_file.schema_arrow

            if parquet_file.metadata.num_columns == 0:
                self._add_validation_error("Parquet file has no columns")
                return False

        except Exception as e:
            self._add_validation_error(f"Failed to read Parquet: {e}")
            return False

        return True

    def parse(self, content: bytes) -> pd.DataFrame:
        """Parse Parquet content into DataFrame.

        Preserves original schema information for later serialization.

        Args:
            content: Raw Parquet bytes

        Returns:
            Parsed DataFrame
        """
        buffer = io.BytesIO(content)
        table = pq.read_table(buffer)

        self._original_schema = table.schema

        df = table.to_pandas()
        df = df.astype(str)
        df = df.replace('nan', '')
        df = df.replace('None', '')

        return df

    def serialize(self, df: pd.DataFrame) -> bytes:
        """Serialize ``df`` to Parquet bytes.

        After PII protection, columns are uniformly cast to ``str`` so the
        original Arrow schema captured at parse-time no longer matches and is
        not reapplied; the writer infers a fresh string-dominated schema.
        """
        table = pa.Table.from_pandas(df, preserve_index=False)

        buffer = io.BytesIO()
        pq.write_table(
            table,
            buffer,
            compression=self._compression,
            use_dictionary=True,
            write_statistics=True
        )

        return buffer.getvalue()

    def get_content_type(self) -> str:
        """Get MIME content type for Parquet."""
        return 'application/octet-stream'

    def _get_format_name(self) -> str:
        """Get format name."""
        return 'Parquet'

    def _extract_metadata(self, df: pd.DataFrame, content: bytes,
                          file_name: str) -> FileMetadata:
        """Extract metadata including Parquet-specific info.

        Args:
            df: Parsed DataFrame
            content: Original file bytes
            file_name: Original file name

        Returns:
            FileMetadata with Parquet details
        """
        metadata = super()._extract_metadata(df, content, file_name)

        if self._original_schema:
            metadata.schema = {
                field.name: str(field.type)
                for field in self._original_schema
            }

        return metadata
