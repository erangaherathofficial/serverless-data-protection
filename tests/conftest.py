"""Pytest configuration and shared fixtures."""

import os
import sys
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

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
    """Mock AWS credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'
    yield
    for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                'AWS_SECURITY_TOKEN', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION']:
        os.environ.pop(key, None)


@pytest.fixture
def env_vars():
    """Set up environment variables for testing."""
    original = os.environ.copy()
    os.environ['AWS_REGION'] = 'eu-west-2'
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
    content = """id,name,email,phone,ssn,address
1,John Smith,john.smith@example.com,+44 7911 123456,AB123456C,"123 Main St, London"
2,Jane Doe,jane.doe@test.org,020 7946 0958,CD789012E,"456 Oak Ave, Manchester"
3,Bob Wilson,bob.wilson@company.co.uk,+44 7700 900123,EF345678G,"789 Pine Rd, Birmingham"
"""
    return content.encode('utf-8')


@pytest.fixture
def sample_json_content() -> bytes:
    """Sample JSON content with PII data."""
    import json
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
                "awsRegion": "eu-west-2",
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
    context.invoked_function_arn = 'arn:aws:lambda:eu-west-2:123456789012:function:sdp-data-protection-test'
    context.memory_limit_in_mb = 1024
    context.aws_request_id = 'test-request-id-12345'
    context.log_group_name = '/aws/lambda/sdp-data-protection-test'
    context.log_stream_name = '2024/01/15/[$LATEST]abc123'
    context.get_remaining_time_in_millis = MagicMock(return_value=300000)
    return context


@pytest.fixture
def sample_protection_policy() -> dict:
    """Sample protection policy configuration."""
    return {
        "version": "1.0",
        "default_protection": "masking",
        "rules": [
            {
                "entity_type": "EMAIL_ADDRESS",
                "protection_method": "sha256_hash",
                "priority": 1
            },
            {
                "entity_type": "PHONE_NUMBER",
                "protection_method": "masking",
                "mask_char": "*",
                "visible_chars": 4,
                "priority": 2
            },
            {
                "entity_type": "CREDIT_CARD",
                "protection_method": "aes256_encrypt",
                "priority": 1
            },
            {
                "entity_type": "UK_NHS",
                "protection_method": "tokenization",
                "priority": 1
            },
            {
                "entity_type": "PERSON",
                "protection_method": "masking",
                "mask_char": "X",
                "visible_chars": 1,
                "priority": 3
            }
        ]
    }


class MockS3Client:
    """Mock S3 client for testing."""

    def __init__(self):
        self._objects = {}

    def get_object(self, Bucket: str, Key: str) -> dict:
        key = f"{Bucket}/{Key}"
        if key not in self._objects:
            raise Exception(f"Object not found: {key}")
        return {'Body': MagicMock(read=lambda: self._objects[key])}

    def put_object(self, Bucket: str, Key: str, Body: bytes, **kwargs) -> dict:
        self._objects[f"{Bucket}/{Key}"] = Body
        return {'ETag': '"abc123"'}

    def add_object(self, bucket: str, key: str, content: bytes):
        self._objects[f"{bucket}/{key}"] = content


@pytest.fixture
def mock_s3_client() -> MockS3Client:
    """Get mock S3 client."""
    return MockS3Client()
