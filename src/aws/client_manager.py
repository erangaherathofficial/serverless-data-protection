"""AWS Client Manager - Singleton pattern for shared AWS resources."""

import os
from threading import Lock
from typing import Optional

import boto3
from botocore.config import Config


class AWSClientManager:
    """Singleton manager for AWS service clients.

    Provides centralized access to S3, DynamoDB, and KMS clients
    with connection pooling and consistent configuration.
    """

    _instance: Optional['AWSClientManager'] = None
    _lock: Lock = Lock()

    def __new__(cls) -> 'AWSClientManager':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self._config = Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            connect_timeout=5,
            read_timeout=30
        )

        self._region = os.environ.get('AWS_REGION', 'eu-west-2')
        self._raw_bucket = os.environ.get('RAW_BUCKET_NAME', '')
        self._secure_bucket = os.environ.get('SECURE_BUCKET_NAME', '')
        self._audit_table = os.environ.get('AUDIT_TABLE_NAME', '')
        self._kms_key_id = os.environ.get('KMS_KEY_ID', '')

        self._s3_client = None
        self._dynamodb_client = None
        self._dynamodb_resource = None
        self._kms_client = None

        self._initialized = True

    @property
    def s3(self):
        """Get S3 client with lazy initialization."""
        if self._s3_client is None:
            self._s3_client = boto3.client(
                's3',
                region_name=self._region,
                config=self._config
            )
        return self._s3_client

    @property
    def dynamodb(self):
        """Get DynamoDB client with lazy initialization."""
        if self._dynamodb_client is None:
            self._dynamodb_client = boto3.client(
                'dynamodb',
                region_name=self._region,
                config=self._config
            )
        return self._dynamodb_client

    @property
    def dynamodb_resource(self):
        """Get DynamoDB resource with lazy initialization."""
        if self._dynamodb_resource is None:
            self._dynamodb_resource = boto3.resource(
                'dynamodb',
                region_name=self._region,
                config=self._config
            )
        return self._dynamodb_resource

    @property
    def kms(self):
        """Get KMS client with lazy initialization."""
        if self._kms_client is None:
            self._kms_client = boto3.client(
                'kms',
                region_name=self._region,
                config=self._config
            )
        return self._kms_client

    @property
    def region(self) -> str:
        """Get configured AWS region."""
        return self._region

    @property
    def raw_bucket(self) -> str:
        """Get raw data bucket name."""
        return self._raw_bucket

    @property
    def secure_bucket(self) -> str:
        """Get secure data bucket name."""
        return self._secure_bucket

    @property
    def audit_table(self) -> str:
        """Get audit DynamoDB table name."""
        return self._audit_table

    @property
    def kms_key_id(self) -> str:
        """Get KMS key ID for encryption."""
        return self._kms_key_id

    def get_object(self, bucket: str, key: str) -> bytes:
        """Download object from S3."""
        response = self.s3.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()

    def put_object(self, bucket: str, key: str, data: bytes,
                   content_type: str = 'application/octet-stream') -> dict:
        """Upload object to S3."""
        return self.s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ContentType=content_type
        )

    def put_audit_record(self, record: dict) -> dict:
        """Write audit record to DynamoDB."""
        table = self.dynamodb_resource.Table(self._audit_table)
        return table.put_item(Item=record)

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (for testing purposes)."""
        with cls._lock:
            cls._instance = None


def get_client_manager() -> AWSClientManager:
    """Get the singleton AWSClientManager instance."""
    return AWSClientManager()
