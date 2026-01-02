"""Unit tests for AWS Client Manager."""

import pytest

from src.aws.client_manager import AWSClientManager, get_client_manager


class TestAWSClientManager:
    """Tests for AWSClientManager singleton."""

    def test_singleton_pattern(self, env_vars):
        """Verify singleton returns same instance."""
        instance1 = AWSClientManager()
        instance2 = AWSClientManager()
        assert instance1 is instance2

    def test_get_client_manager_returns_singleton(self, env_vars):
        """Verify get_client_manager returns singleton."""
        instance1 = get_client_manager()
        instance2 = get_client_manager()
        assert instance1 is instance2

    def test_reset_instance(self, env_vars):
        """Verify reset creates new instance."""
        instance1 = AWSClientManager()
        AWSClientManager.reset_instance()
        instance2 = AWSClientManager()
        assert instance1 is not instance2

    def test_environment_variables_loaded(self, env_vars):
        """Verify environment variables are correctly loaded."""
        manager = get_client_manager()
        assert manager.region == 'eu-west-2'
        assert manager.raw_bucket == 'test-raw-bucket'
        assert manager.secure_bucket == 'test-secure-bucket'
        assert manager.audit_table == 'test-audit-table'
        assert manager.kms_key_id == 'test-kms-key-id'

    def test_s3_client_lazy_initialization(self, env_vars, aws_credentials):
        """Verify S3 client is lazily initialized."""
        manager = get_client_manager()
        assert manager._s3_client is None
        _ = manager.s3
        assert manager._s3_client is not None

    def test_dynamodb_client_lazy_initialization(self, env_vars, aws_credentials):
        """Verify DynamoDB client is lazily initialized."""
        manager = get_client_manager()
        assert manager._dynamodb_client is None
        _ = manager.dynamodb
        assert manager._dynamodb_client is not None

    def test_kms_client_lazy_initialization(self, env_vars, aws_credentials):
        """Verify KMS client is lazily initialized."""
        manager = get_client_manager()
        assert manager._kms_client is None
        _ = manager.kms
        assert manager._kms_client is not None
