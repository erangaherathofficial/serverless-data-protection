"""Unit tests for Lambda handler."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.lambda_handler import (
    ProcessingError,
    _build_response,
    _get_content_type,
    _get_file_extension,
    handler,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_file_extension_csv(self):
        """Test CSV extension extraction."""
        assert _get_file_extension('data/file.csv') == '.csv'

    def test_get_file_extension_json(self):
        """Test JSON extension extraction."""
        assert _get_file_extension('data/file.json') == '.json'

    def test_get_file_extension_parquet(self):
        """Test Parquet extension extraction."""
        assert _get_file_extension('data/file.parquet') == '.parquet'

    def test_get_file_extension_uppercase(self):
        """Test uppercase extension is lowercased."""
        assert _get_file_extension('data/file.CSV') == '.csv'

    def test_get_file_extension_no_extension(self):
        """Test file without extension."""
        assert _get_file_extension('data/file') == ''

    def test_get_content_type_csv(self):
        """Test CSV content type."""
        assert _get_content_type('.csv') == 'text/csv'

    def test_get_content_type_json(self):
        """Test JSON content type."""
        assert _get_content_type('.json') == 'application/json'

    def test_get_content_type_parquet(self):
        """Test Parquet content type."""
        assert _get_content_type('.parquet') == 'application/octet-stream'

    def test_get_content_type_unknown(self):
        """Test unknown content type defaults to octet-stream."""
        assert _get_content_type('.xyz') == 'application/octet-stream'

    def test_build_response_success(self):
        """Test successful response building."""
        response = _build_response(200, 'Success', [{'id': 1}], [])
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['message'] == 'Success'
        assert body['processed'] == 1
        assert body['failed'] == 0

    def test_build_response_with_errors(self):
        """Test response with errors."""
        response = _build_response(207, 'Partial', [{'id': 1}], [{'error': 'fail'}])
        assert response['statusCode'] == 207
        body = json.loads(response['body'])
        assert body['failed'] == 1


class TestProcessingError:
    """Tests for ProcessingError exception."""

    def test_processing_error_attributes(self):
        """Test ProcessingError stores bucket and key."""
        error = ProcessingError('Test error', 'my-bucket', 'my-key')
        assert str(error) == 'Test error'
        assert error.bucket == 'my-bucket'
        assert error.key == 'my-key'


class TestHandler:
    """Tests for Lambda handler function."""

    def test_handler_empty_event(self, env_vars, mock_lambda_context):
        """Test handler with empty event."""
        result = handler({}, mock_lambda_context)
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['processed'] == 0

    def test_handler_no_records(self, env_vars, mock_lambda_context):
        """Test handler with no records."""
        result = handler({'Records': []}, mock_lambda_context)
        assert result['statusCode'] == 200

    @patch('src.lambda_handler.get_client_manager')
    def test_handler_unsupported_format(self, mock_cm, env_vars,
                                         mock_lambda_context, sample_s3_event):
        """Test handler rejects unsupported file formats."""
        sample_s3_event['Records'][0]['s3']['object']['key'] = 'data.txt'
        result = handler(sample_s3_event, mock_lambda_context)
        assert result['statusCode'] == 207
        body = json.loads(result['body'])
        assert body['failed'] == 1

    @patch('src.lambda_handler.get_client_manager')
    def test_handler_processes_csv(self, mock_cm, env_vars,
                                    mock_lambda_context, sample_s3_event,
                                    sample_csv_content):
        """Test handler processes CSV file."""
        mock_manager = MagicMock()
        mock_manager.get_object.return_value = sample_csv_content
        mock_manager.secure_bucket = 'test-secure-bucket'
        mock_cm.return_value = mock_manager

        result = handler(sample_s3_event, mock_lambda_context)
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['processed'] == 1
