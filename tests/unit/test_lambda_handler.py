"""Unit tests for Lambda handler."""

import json
import pytest
from unittest.mock import MagicMock, patch

from src.lambda_handler import (
    ProcessingError,
    _build_response,
    handler,
)

pytestmark = pytest.mark.unit


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_build_response_success(self):
        response = _build_response(200, 'Success', [{'id': 1}], [])
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['message'] == 'Success'
        assert body['processed'] == 1
        assert body['failed'] == 0

    def test_build_response_with_errors(self):
        response = _build_response(
            207, 'Partial', [{'id': 1}], [{'error': 'fail'}]
        )
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
    def test_handler_unsupported_format(
            self, mock_cm, env_vars, mock_lambda_context, sample_s3_event
    ):
        """Test handler rejects unsupported file formats."""
        sample_s3_event['Records'][0]['s3']['object']['key'] = 'data.txt'
        result = handler(sample_s3_event, mock_lambda_context)
        assert result['statusCode'] == 207
        body = json.loads(result['body'])
        assert body['failed'] == 1

    @patch('src.lambda_handler.get_client_manager')
    def test_handler_processes_csv(
            self, mock_cm, env_vars, mock_lambda_context,
            sample_s3_event, sample_csv_content
    ):
        """Test handler processes CSV file."""
        mock_manager = MagicMock()
        mock_manager.get_object.return_value = sample_csv_content
        mock_manager.secure_bucket = 'test-secure-bucket'
        mock_cm.return_value = mock_manager

        result = handler(sample_s3_event, mock_lambda_context)
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['processed'] == 1
