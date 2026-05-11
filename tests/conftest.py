"""Pytest configuration and shared fixtures."""

import json
import os
import pytest
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton instances before each test."""
    from src.aws.client_manager import AWSClientManager
    AWSClientManager.reset_instance()
    yield
    AWSClientManager.reset_instance()


@pytest.fixture
def aws_credentials():
    """Set placeholder AWS credentials so boto3 client instantiation succeeds."""
    original = os.environ.copy()
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    yield
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def env_vars():
    """Set up environment variables for testing."""
    original = os.environ.copy()
    os.environ['AWS_REGION'] = 'us-east-1'
    os.environ['RAW_BUCKET_NAME'] = 'test-raw-bucket'
    os.environ['SECURE_BUCKET_NAME'] = 'test-secure-bucket'
    os.environ['AUDIT_TABLE_NAME'] = 'test-audit-table'
    os.environ['KMS_KEY_ID'] = 'test-kms-key-id'
    os.environ['ENVIRONMENT'] = 'test'
    os.environ['LOG_LEVEL'] = 'DEBUG'
    yield
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def sample_csv_content() -> bytes:
    """Sample CSV content with PII data."""
    rows = [
        "id,name,email,phone,ssn,address",
        '1,John Smith,john.smith@example.com,'
        '+44 7911 123456,AB123456C,"123 Main St, London"',
        '2,Jane Doe,jane.doe@test.org,'
        '020 7946 0958,CD789012E,"456 Oak Ave, Manchester"',
        '3,Bob Wilson,bob.wilson@company.co.uk,'
        '+44 7700 900123,EF345678G,"789 Pine Rd, Birmingham"',
    ]
    content = "\n".join(rows) + "\n"
    return content.encode('utf-8')


@pytest.fixture
def sample_json_content() -> bytes:
    """Sample JSON content with PII data."""
    data = {
        "records": [
            {
                "id": 1,
                "name": "John Smith",
                "email": "john.smith@example.com",
                "phone": "+44 7911 123456",
                "ssn": "AB123456C",
                "address": "123 Main St, London"
            },
            {
                "id": 2,
                "name": "Jane Doe",
                "email": "jane.doe@test.org",
                "phone": "020 7946 0958",
                "ssn": "CD789012E",
                "address": "456 Oak Ave, Manchester"
            }
        ]
    }
    return json.dumps(data, indent=2).encode('utf-8')


@pytest.fixture
def sample_s3_event() -> dict:
    """Sample S3 event for Lambda testing."""
    return {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "awsRegion": "us-east-1",
                "eventTime": "2024-01-15T12:00:00.000Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "s3SchemaVersion": "1.0",
                    "bucket": {
                        "name": "test-raw-bucket",
                        "arn": "arn:aws:s3:::test-raw-bucket"
                    },
                    "object": {
                        "key": "test-data.csv",
                        "size": 1024,
                        "eTag": "abc123"
                    }
                }
            }
        ]
    }


@pytest.fixture
def mock_lambda_context():
    """Mock AWS Lambda context object."""
    context = MagicMock()
    context.function_name = 'sdp-data-protection-test'
    context.function_version = '$LATEST'
    arn = 'arn:aws:lambda:us-east-1:123456789012:function:'
    context.invoked_function_arn = arn + 'sdp-data-protection-test'
    context.memory_limit_in_mb = 1024
    context.aws_request_id = 'test-request-id-12345'
    context.log_group_name = '/aws/lambda/sdp-data-protection-test'
    context.log_stream_name = '2024/01/15/[$LATEST]abc123'
    context.get_remaining_time_in_millis = MagicMock(return_value=300000)
    return context
