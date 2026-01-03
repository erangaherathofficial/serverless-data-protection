"""Unit tests for file handlers."""

import io
import json

import pandas as pd
import pytest
from src.handlers.base_handler import FileMetadata, ProcessedData
from src.handlers.csv_handler import CSVHandler
from src.handlers.handler_factory import (
    HandlerFactory,
    UnsupportedFormatError,
    get_handler,
)
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler


class TestCSVHandler:
    """Tests for CSV handler."""

    def test_validate_valid_csv(self, sample_csv_content):
        """Test validation of valid CSV."""
        handler = CSVHandler()
        assert handler.validate(sample_csv_content, 'test.csv') is True
        assert len(handler.validation_errors) == 0

    def test_validate_empty_file(self):
        """Test validation rejects empty file."""
        handler = CSVHandler()
        assert handler.validate(b'', 'test.csv') is False
        assert 'empty' in handler.validation_errors[0].lower()

    def test_validate_invalid_encoding(self):
        """Test validation rejects invalid encoding."""
        handler = CSVHandler()
        invalid_bytes = b'\xff\xfe'
        assert handler.validate(invalid_bytes, 'test.csv') is False
        assert 'encoding' in handler.validation_errors[0].lower()

    def test_validate_inconsistent_columns(self):
        """Test validation rejects inconsistent column counts."""
        handler = CSVHandler()
        content = b'a,b,c\n1,2\n3,4,5'
        assert handler.validate(content, 'test.csv') is False

    def test_parse_csv(self, sample_csv_content):
        """Test CSV parsing into DataFrame."""
        handler = CSVHandler()
        handler.validate(sample_csv_content, 'test.csv')
        df = handler.parse(sample_csv_content)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 3
        assert 'email' in df.columns

    def test_serialize_csv(self, sample_csv_content):
        """Test DataFrame serialization to CSV."""
        handler = CSVHandler()
        handler.validate(sample_csv_content, 'test.csv')
        df = handler.parse(sample_csv_content)

        result = handler.serialize(df)
        assert isinstance(result, bytes)
        assert b'email' in result

    def test_process_csv(self, sample_csv_content):
        """Test full processing pipeline."""
        handler = CSVHandler()
        result = handler.process(sample_csv_content, 'test.csv')

        assert isinstance(result, ProcessedData)
        assert isinstance(result.dataframe, pd.DataFrame)
        assert isinstance(result.metadata, FileMetadata)
        assert result.metadata.file_format == 'CSV'
        assert result.metadata.row_count == 3

    def test_delimiter_detection(self):
        """Test automatic delimiter detection."""
        handler = CSVHandler()
        content = b'a;b;c\n1;2;3\n4;5;6'
        handler.validate(content, 'test.csv')
        assert handler.delimiter == ';'

    def test_content_type(self):
        """Test content type is correct."""
        handler = CSVHandler()
        assert handler.get_content_type() == 'text/csv'

    def test_supports_extension(self):
        """Test extension support check."""
        assert CSVHandler.supports_extension('.csv') is True
        assert CSVHandler.supports_extension('csv') is True
        assert CSVHandler.supports_extension('.json') is False


class TestJSONHandler:
    """Tests for JSON handler."""

    def test_validate_array_json(self, sample_json_content):
        """Test validation of JSON array format."""
        content = b'[{"a": 1}, {"a": 2}]'
        handler = JSONHandler()
        assert handler.validate(content, 'test.json') is True
        assert handler.detected_format == 'array'

    def test_validate_nested_json(self, sample_json_content):
        """Test validation of nested JSON with records."""
        handler = JSONHandler()
        assert handler.validate(sample_json_content, 'test.json') is True
        assert handler.detected_format == 'nested'
        assert handler.records_path == 'records'

    def test_validate_ndjson(self):
        """Test validation of newline-delimited JSON."""
        content = b'{"a": 1}\n{"a": 2}\n{"a": 3}'
        handler = JSONHandler()
        assert handler.validate(content, 'test.json') is True
        assert handler.detected_format == 'ndjson'

    def test_validate_empty_file(self):
        """Test validation rejects empty file."""
        handler = JSONHandler()
        assert handler.validate(b'', 'test.json') is False

    def test_validate_invalid_json(self):
        """Test validation rejects invalid JSON."""
        handler = JSONHandler()
        assert handler.validate(b'{invalid}', 'test.json') is False

    def test_parse_array_json(self):
        """Test parsing JSON array."""
        content = b'[{"name": "John", "age": "30"}, '
        content += b'{"name": "Jane", "age": "25"}]'
        handler = JSONHandler()
        handler.validate(content, 'test.json')
        df = handler.parse(content)

        assert len(df) == 2
        assert 'name' in df.columns

    def test_parse_nested_json(self, sample_json_content):
        """Test parsing nested JSON."""
        handler = JSONHandler()
        handler.validate(sample_json_content, 'test.json')
        df = handler.parse(sample_json_content)

        assert len(df) == 2
        assert 'email' in df.columns

    def test_serialize_json(self, sample_json_content):
        """Test DataFrame serialization to JSON."""
        handler = JSONHandler()
        handler.validate(sample_json_content, 'test.json')
        df = handler.parse(sample_json_content)

        result = handler.serialize(df)
        assert isinstance(result, bytes)

        data = json.loads(result)
        assert 'records' in data

    def test_serialize_ndjson(self):
        """Test NDJSON serialization."""
        content = b'{"a": "1"}\n{"a": "2"}'
        handler = JSONHandler()
        handler.validate(content, 'test.json')
        df = handler.parse(content)

        result = handler.serialize(df)
        lines = result.decode().strip().split('\n')
        assert len(lines) == 2

    def test_custom_records_path(self):
        """Test custom records path."""
        content = b'{"response": {"data": [{"x": 1}]}}'
        handler = JSONHandler(records_path='response.data')
        assert handler.validate(content, 'test.json') is True
        assert handler.records_path == 'response.data'

    def test_content_type(self):
        """Test content type is correct."""
        handler = JSONHandler()
        assert handler.get_content_type() == 'application/json'


class TestParquetHandler:
    """Tests for Parquet handler."""

    @pytest.fixture
    def sample_parquet_content(self) -> bytes:
        """Create sample Parquet content."""
        df = pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John', 'Jane', 'Bob'],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com']
        })
        buffer = io.BytesIO()
        df.to_parquet(buffer, index=False)
        return buffer.getvalue()

    def test_validate_valid_parquet(self, sample_parquet_content):
        """Test validation of valid Parquet."""
        handler = ParquetHandler()
        assert handler.validate(sample_parquet_content, 'test.parquet') is True
        assert handler.original_schema is not None

    def test_validate_empty_file(self):
        """Test validation rejects empty file."""
        handler = ParquetHandler()
        assert handler.validate(b'', 'test.parquet') is False

    def test_validate_invalid_parquet(self):
        """Test validation rejects non-Parquet file."""
        handler = ParquetHandler()
        assert handler.validate(b'not parquet data', 'test.parquet') is False

    def test_validate_missing_magic_bytes(self):
        """Test validation checks magic bytes."""
        handler = ParquetHandler()
        content = b'XXXX' + b'\x00' * 100 + b'XXXX'
        assert handler.validate(content, 'test.parquet') is False
        assert 'magic bytes' in handler.validation_errors[0].lower()

    def test_parse_parquet(self, sample_parquet_content):
        """Test Parquet parsing into DataFrame."""
        handler = ParquetHandler()
        handler.validate(sample_parquet_content, 'test.parquet')
        df = handler.parse(sample_parquet_content)

        assert len(df) == 3
        assert 'email' in df.columns

    def test_serialize_parquet(self, sample_parquet_content):
        """Test DataFrame serialization to Parquet."""
        handler = ParquetHandler()
        handler.validate(sample_parquet_content, 'test.parquet')
        df = handler.parse(sample_parquet_content)

        result = handler.serialize(df)
        assert isinstance(result, bytes)
        assert result[:4] == b'PAR1'

    def test_process_parquet(self, sample_parquet_content):
        """Test full processing pipeline."""
        handler = ParquetHandler()
        result = handler.process(sample_parquet_content, 'test.parquet')

        assert isinstance(result, ProcessedData)
        assert result.metadata.file_format == 'Parquet'

    def test_get_schema_info(self, sample_parquet_content):
        """Test schema info extraction."""
        handler = ParquetHandler()
        handler.validate(sample_parquet_content, 'test.parquet')
        handler.parse(sample_parquet_content)

        schema_info = handler.get_schema_info()
        assert 'columns' in schema_info
        assert len(schema_info['columns']) == 3

    def test_content_type(self):
        """Test content type is correct."""
        handler = ParquetHandler()
        assert handler.get_content_type() == 'application/octet-stream'


class TestHandlerFactory:
    """Tests for handler factory."""

    def test_get_handler_csv(self):
        """Test factory returns CSV handler."""
        handler = HandlerFactory.get_handler('data/file.csv')
        assert isinstance(handler, CSVHandler)

    def test_get_handler_json(self):
        """Test factory returns JSON handler."""
        handler = HandlerFactory.get_handler('file.json')
        assert isinstance(handler, JSONHandler)

    def test_get_handler_parquet(self):
        """Test factory returns Parquet handler."""
        handler = HandlerFactory.get_handler('file.parquet')
        assert isinstance(handler, ParquetHandler)

    def test_get_handler_uppercase(self):
        """Test factory handles uppercase extensions."""
        handler = HandlerFactory.get_handler('file.CSV')
        assert isinstance(handler, CSVHandler)

    def test_get_handler_unsupported(self):
        """Test factory raises for unsupported format."""
        with pytest.raises(UnsupportedFormatError) as exc:
            HandlerFactory.get_handler('file.txt')
        assert exc.value.extension == '.txt'

    def test_get_handler_for_extension(self):
        """Test get handler by extension."""
        handler = HandlerFactory.get_handler_for_extension('csv')
        assert isinstance(handler, CSVHandler)

        handler = HandlerFactory.get_handler_for_extension('.json')
        assert isinstance(handler, JSONHandler)

    def test_is_supported(self):
        """Test support checking."""
        assert HandlerFactory.is_supported('file.csv') is True
        assert HandlerFactory.is_supported('file.json') is True
        assert HandlerFactory.is_supported('file.parquet') is True
        assert HandlerFactory.is_supported('file.txt') is False

    def test_get_supported_extensions(self):
        """Test listing supported extensions."""
        extensions = HandlerFactory.get_supported_extensions()
        assert '.csv' in extensions
        assert '.json' in extensions
        assert '.parquet' in extensions

    def test_convenience_function(self):
        """Test get_handler convenience function."""
        handler = get_handler('test.csv')
        assert isinstance(handler, CSVHandler)

    def test_handler_with_kwargs(self):
        """Test factory passes kwargs to handler."""
        handler = HandlerFactory.get_handler('file.csv', delimiter=';')
        assert handler._delimiter == ';'
