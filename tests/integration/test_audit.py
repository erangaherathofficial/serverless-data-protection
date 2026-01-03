"""Integration tests for audit trail."""

import json
from unittest.mock import MagicMock

import pytest
from src.audit.cloudwatch_logger import (
    AuditLogEntry,
    CloudWatchLogger,
    MetricData,
    MetricUnit,
)
from src.audit.dynamodb_writer import (
    DetectionRecord,
    DynamoDBWriter,
    ProcessingRecord,
    ProtectionRecord,
)


class TestCloudWatchLogger:
    """Tests for CloudWatch logger."""

    @pytest.fixture
    def logger(self):
        """Create logger with metrics disabled."""
        return CloudWatchLogger(
            environment='test',
            enable_metrics=False
        )

    def test_log_processing_start(self, logger, caplog):
        """Test logging processing start."""
        import logging
        caplog.set_level(logging.INFO)

        logger.log_processing_start(
            request_id='req-123',
            file_name='test.csv',
            file_size=1024,
            file_format='CSV'
        )

        assert len(logger._metrics_buffer) >= 2

    def test_log_processing_complete(self, logger):
        """Test logging processing completion."""
        logger.log_processing_complete(
            request_id='req-123',
            file_name='test.csv',
            duration_ms=150.5,
            success=True,
            detection_summary={
                'entities_found': 10,
                'entity_types': {'EMAIL_ADDRESS': 5, 'PHONE_NUMBER': 5}
            },
            protection_summary={
                'protections_applied': 10
            }
        )

        assert len(logger._metrics_buffer) > 0

    def test_log_detection_results(self, logger):
        """Test logging detection results."""
        logger.log_detection_results(
            request_id='req-123',
            file_name='test.csv',
            entities_found=15,
            entity_types={'EMAIL_ADDRESS': 10, 'CREDIT_CARD': 5},
            columns_with_pii=['email', 'card'],
            duration_ms=50.0
        )

    def test_log_protection_applied(self, logger):
        """Test logging protection application."""
        logger.log_protection_applied(
            request_id='req-123',
            file_name='test.csv',
            protection_method='sha256_hash',
            entity_type='EMAIL_ADDRESS',
            column='email',
            count=10
        )

        assert any(
            m.name == 'ProtectionByMethod'
            for m in logger._metrics_buffer
        )

    def test_log_error(self, logger):
        """Test logging errors."""
        logger.log_error(
            request_id='req-123',
            file_name='test.csv',
            error_type='ValidationError',
            error_message='Invalid file format',
            stage='validate'
        )

        assert any(
            m.name == 'ProcessingErrors'
            for m in logger._metrics_buffer
        )

    def test_log_schema_validation(self, logger):
        """Test logging schema validation."""
        logger.log_schema_validation(
            request_id='req-123',
            file_name='test.csv',
            is_valid=True,
            errors=0,
            warnings=2
        )

        assert any(
            m.name == 'SchemaValidation'
            for m in logger._metrics_buffer
        )

    def test_metrics_buffer_flush(self, logger):
        """Test metrics buffer flushing."""
        for i in range(25):
            logger._record_metric(MetricData(
                name=f'TestMetric{i}',
                value=1.0
            ))

        assert len(logger._metrics_buffer) < 25

    def test_create_dashboard_metrics(self, logger):
        """Test dashboard configuration generation."""
        config = logger.create_dashboard_metrics()

        assert 'widgets' in config
        assert len(config['widgets']) > 0


class TestAuditLogEntry:
    """Tests for AuditLogEntry dataclass."""

    def test_create_entry(self):
        """Test creating audit log entry."""
        entry = AuditLogEntry(
            event_type='TEST_EVENT',
            request_id='req-123',
            file_name='test.csv',
            status='success',
            duration_ms=100.5,
            details={'key': 'value'}
        )

        assert entry.event_type == 'TEST_EVENT'
        assert entry.timestamp is not None

    def test_entry_to_dict(self):
        """Test entry serialization."""
        entry = AuditLogEntry(
            event_type='TEST',
            request_id='req-123',
            file_name='test.csv',
            status='success',
            duration_ms=100.0
        )

        data = entry.to_dict()
        assert data['event_type'] == 'TEST'
        assert 'timestamp' in data

    def test_entry_to_json(self):
        """Test JSON serialization."""
        entry = AuditLogEntry(
            event_type='TEST',
            request_id='req-123',
            file_name='test.csv',
            status='success',
            duration_ms=100.0
        )

        json_str = entry.to_json()
        parsed = json.loads(json_str)
        assert parsed['event_type'] == 'TEST'


class TestMetricData:
    """Tests for MetricData dataclass."""

    def test_create_metric(self):
        """Test creating metric data."""
        metric = MetricData(
            name='TestMetric',
            value=42.0,
            unit=MetricUnit.COUNT,
            dimensions={'Env': 'test'}
        )

        assert metric.name == 'TestMetric'
        assert metric.value == 42.0

    def test_metric_to_cloudwatch_format(self):
        """Test CloudWatch format conversion."""
        metric = MetricData(
            name='TestMetric',
            value=100.0,
            unit=MetricUnit.MILLISECONDS,
            dimensions={'Service': 'DataProtection'}
        )

        cw_format = metric.to_cloudwatch_format()

        assert cw_format['MetricName'] == 'TestMetric'
        assert cw_format['Value'] == 100.0
        assert cw_format['Unit'] == 'Milliseconds'
        assert len(cw_format['Dimensions']) == 1


class TestDynamoDBWriter:
    """Tests for DynamoDB writer."""

    @pytest.fixture
    def writer(self):
        """Create writer without table."""
        return DynamoDBWriter(table_name='')

    @pytest.fixture
    def mock_writer(self):
        """Create writer with mock table."""
        writer = DynamoDBWriter(table_name='test-audit-table')
        writer._table = MagicMock()
        return writer

    def test_write_processing_record_no_table(self, writer):
        """Test writing without table configured."""
        result = writer.write_processing_record(
            request_id='req-123',
            source_bucket='test-bucket',
            source_key='data/test.csv',
            file_format='CSV',
            file_size=1024,
            success=True,
            duration_ms=150.0
        )

        assert result is None

    def test_write_processing_record_with_mock(self, mock_writer):
        """Test writing processing record."""
        result = mock_writer.write_processing_record(
            request_id='req-123',
            source_bucket='test-bucket',
            source_key='data/test.csv',
            file_format='CSV',
            file_size=1024,
            success=True,
            duration_ms=150.0,
            secure_bucket='secure-bucket',
            secure_key='protected/data/test.csv'
        )

        mock_writer._table.put_item.assert_called_once()
        assert result is not None

    def test_write_detection_record(self, mock_writer):
        """Test writing detection record."""
        result = mock_writer.write_detection_record(
            request_id='req-123',
            file_name='test.csv',
            total_entities=15,
            entity_types={'EMAIL_ADDRESS': 10, 'PHONE_NUMBER': 5},
            columns_with_pii=['email', 'phone'],
            cells_scanned=100,
            cells_with_pii=15,
            duration_ms=50.0
        )

        mock_writer._table.put_item.assert_called_once()
        assert result is not None

    def test_write_protection_record(self, mock_writer):
        """Test writing protection record."""
        result = mock_writer.write_protection_record(
            request_id='req-123',
            file_name='test.csv',
            protections_applied=15,
            methods_used={'sha256_hash': 10, 'masking': 5},
            duration_ms=30.0
        )

        mock_writer._table.put_item.assert_called_once()
        assert result is not None

    def test_write_entity_records(self, mock_writer):
        """Test writing entity records."""
        entities = [
            {
                'entity_type': 'EMAIL_ADDRESS',
                'column_name': 'email',
                'row_index': 0,
                'protection_method': 'sha256_hash',
                'score': 0.95
            },
            {
                'entity_type': 'PHONE_NUMBER',
                'column_name': 'phone',
                'row_index': 1,
                'protection_method': 'masking',
                'score': 0.85
            }
        ]

        count = mock_writer.write_entity_records(
            request_id='req-123',
            file_name='test.csv',
            entities=entities
        )

        assert count == 2
        assert mock_writer._table.put_item.call_count == 2


class TestProcessingRecord:
    """Tests for ProcessingRecord dataclass."""

    def test_create_record(self):
        """Test creating processing record."""
        record = ProcessingRecord(
            pk='FILE#bucket/key',
            sk='PROCESS#2024-01-15T12:00:00',
            request_id='req-123',
            source_bucket='bucket',
            source_key='key',
            file_format='CSV',
            file_size=1024,
            success=True,
            duration_ms=150,
            timestamp='2024-01-15T12:00:00Z'
        )

        assert record.gsi1pk.startswith('DATE#')
        assert record.gsi1sk.startswith('FILE#')

    def test_record_with_error(self):
        """Test record with error."""
        record = ProcessingRecord(
            pk='FILE#bucket/key',
            sk='PROCESS#2024-01-15T12:00:00',
            request_id='req-123',
            source_bucket='bucket',
            source_key='key',
            file_format='CSV',
            file_size=1024,
            success=False,
            duration_ms=50,
            timestamp='2024-01-15T12:00:00Z',
            error='Validation failed'
        )

        assert record.success is False
        assert record.error == 'Validation failed'


class TestDetectionRecord:
    """Tests for DetectionRecord dataclass."""

    def test_create_record(self):
        """Test creating detection record."""
        record = DetectionRecord(
            pk='FILE#test.csv',
            sk='DETECTION#2024-01-15T12:00:00',
            request_id='req-123',
            file_name='test.csv',
            timestamp='2024-01-15T12:00:00Z',
            total_entities=15,
            entity_types={'EMAIL_ADDRESS': 10, 'PHONE_NUMBER': 5},
            columns_with_pii=['email', 'phone'],
            cells_scanned=100,
            cells_with_pii=15,
            detection_duration_ms=50
        )

        assert record.total_entities == 15
        assert record.gsi1pk.startswith('DATE#')


class TestProtectionRecord:
    """Tests for ProtectionRecord dataclass."""

    def test_create_record(self):
        """Test creating protection record."""
        record = ProtectionRecord(
            pk='FILE#test.csv',
            sk='PROTECTION#2024-01-15T12:00:00',
            request_id='req-123',
            file_name='test.csv',
            timestamp='2024-01-15T12:00:00Z',
            protections_applied=15,
            methods_used={'sha256_hash': 10, 'masking': 5},
            protection_duration_ms=30
        )

        assert record.protections_applied == 15
        assert 'sha256_hash' in record.methods_used


class TestAuditIntegration:
    """Integration tests combining logger and writer."""

    @pytest.mark.integration
    def test_full_audit_flow(self):
        """Test complete audit flow."""
        logger = CloudWatchLogger(enable_metrics=False)
        _ = DynamoDBWriter(table_name='')

        logger.log_processing_start(
            request_id='req-123',
            file_name='test.csv',
            file_size=1024,
            file_format='CSV'
        )

        logger.log_detection_results(
            request_id='req-123',
            file_name='test.csv',
            entities_found=10,
            entity_types={'EMAIL_ADDRESS': 10},
            columns_with_pii=['email'],
            duration_ms=50.0
        )

        logger.log_processing_complete(
            request_id='req-123',
            file_name='test.csv',
            duration_ms=200.0,
            success=True,
            detection_summary={'entities_found': 10},
            protection_summary={'protections_applied': 10}
        )

        assert len(logger._metrics_buffer) > 0
