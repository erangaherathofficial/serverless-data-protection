"""CloudWatch logging and metrics for audit trail."""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class MetricUnit(Enum):
    """CloudWatch metric units."""
    COUNT = 'Count'
    SECONDS = 'Seconds'
    MILLISECONDS = 'Milliseconds'
    BYTES = 'Bytes'
    PERCENT = 'Percent'
    NONE = 'None'


@dataclass
class MetricData:
    """CloudWatch metric data point."""

    name: str
    value: float
    unit: MetricUnit = MetricUnit.COUNT
    dimensions: dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None

    def to_cloudwatch_format(self) -> dict:
        """Convert to CloudWatch PutMetricData format."""
        metric = {
            'MetricName': self.name,
            'Value': self.value,
            'Unit': self.unit.value,
        }

        if self.dimensions:
            metric['Dimensions'] = [
                {'Name': k, 'Value': v}
                for k, v in self.dimensions.items()
            ]

        if self.timestamp:
            metric['Timestamp'] = self.timestamp.isoformat()

        return metric


@dataclass
class AuditLogEntry:
    """Structured audit log entry."""

    event_type: str
    request_id: str
    file_name: str
    status: str
    duration_ms: float
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'event_type': self.event_type,
            'request_id': self.request_id,
            'file_name': self.file_name,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'timestamp': self.timestamp,
            **self.details
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class CloudWatchLogger:
    """CloudWatch logger for audit trail and metrics.

    Provides structured logging and custom metrics for:
    - Processing events
    - PII detection statistics
    - Protection operations
    - Error tracking
    - Performance metrics
    """

    NAMESPACE = 'ServerlessDataProtection'

    def __init__(
        self,
        environment: Optional[str] = None,
        enable_metrics: bool = True,
        log_level: int = logging.INFO
    ) -> None:
        """Initialize CloudWatch logger.

        Args:
            environment: Environment name (dev/staging/prod)
            enable_metrics: Whether to publish CloudWatch metrics
            log_level: Logging level
        """
        self._environment = environment or os.environ.get('ENVIRONMENT', 'dev')
        self._enable_metrics = enable_metrics
        self._cloudwatch_client = None
        self._metrics_buffer: list[MetricData] = []
        self._buffer_size = 20

        self._logger = logging.getLogger('audit')
        self._logger.setLevel(log_level)

        self._default_dimensions = {
            'Environment': self._environment
        }

    @property
    def cloudwatch(self):
        """Get CloudWatch client (lazy initialization)."""
        if self._cloudwatch_client is None and self._enable_metrics:
            try:
                import boto3
                self._cloudwatch_client = boto3.client('cloudwatch')
            except Exception as e:
                logger.warning(f"Failed to create CloudWatch client: {e}")
        return self._cloudwatch_client

    def log_processing_start(
        self,
        request_id: str,
        file_name: str,
        file_size: int,
        file_format: str
    ) -> None:
        """Log start of file processing.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            file_size: File size in bytes
            file_format: File format (CSV/JSON/Parquet)
        """
        entry = AuditLogEntry(
            event_type='PROCESSING_START',
            request_id=request_id,
            file_name=file_name,
            status='started',
            duration_ms=0,
            details={
                'file_size': file_size,
                'file_format': file_format
            }
        )

        self._logger.info(entry.to_json())

        self._record_metric(MetricData(
            name='ProcessingStarted',
            value=1,
            unit=MetricUnit.COUNT,
            dimensions={'FileFormat': file_format}
        ))

        self._record_metric(MetricData(
            name='FileSizeBytes',
            value=file_size,
            unit=MetricUnit.BYTES,
            dimensions={'FileFormat': file_format}
        ))

    def log_processing_complete(
        self,
        request_id: str,
        file_name: str,
        duration_ms: float,
        success: bool,
        detection_summary: Optional[dict] = None,
        protection_summary: Optional[dict] = None
    ) -> None:
        """Log completion of file processing.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            duration_ms: Processing duration
            success: Whether processing succeeded
            detection_summary: PII detection results
            protection_summary: Protection results
        """
        entry = AuditLogEntry(
            event_type='PROCESSING_COMPLETE',
            request_id=request_id,
            file_name=file_name,
            status='success' if success else 'failed',
            duration_ms=duration_ms,
            details={
                'detection_summary': detection_summary,
                'protection_summary': protection_summary
            }
        )

        self._logger.info(entry.to_json())

        self._record_metric(MetricData(
            name='ProcessingCompleted',
            value=1,
            unit=MetricUnit.COUNT,
            dimensions={'Status': 'Success' if success else 'Failed'}
        ))

        self._record_metric(MetricData(
            name='ProcessingDuration',
            value=duration_ms,
            unit=MetricUnit.MILLISECONDS
        ))

        if detection_summary:
            entities_found = detection_summary.get('entities_found', 0)
            self._record_metric(MetricData(
                name='EntitiesDetected',
                value=entities_found,
                unit=MetricUnit.COUNT
            ))

            for entity_type, count in detection_summary.get('entity_types', {}).items():
                self._record_metric(MetricData(
                    name='EntityTypeCount',
                    value=count,
                    unit=MetricUnit.COUNT,
                    dimensions={'EntityType': entity_type}
                ))

        if protection_summary:
            protections = protection_summary.get('protections_applied', 0)
            self._record_metric(MetricData(
                name='ProtectionsApplied',
                value=protections,
                unit=MetricUnit.COUNT
            ))

    def log_detection_results(
        self,
        request_id: str,
        file_name: str,
        entities_found: int,
        entity_types: dict[str, int],
        columns_with_pii: list[str],
        duration_ms: float
    ) -> None:
        """Log PII detection results.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            entities_found: Total entities detected
            entity_types: Count by entity type
            columns_with_pii: Columns containing PII
            duration_ms: Detection duration
        """
        entry = AuditLogEntry(
            event_type='PII_DETECTION',
            request_id=request_id,
            file_name=file_name,
            status='completed',
            duration_ms=duration_ms,
            details={
                'entities_found': entities_found,
                'entity_types': entity_types,
                'columns_with_pii': columns_with_pii
            }
        )

        self._logger.info(entry.to_json())

    def log_protection_applied(
        self,
        request_id: str,
        file_name: str,
        protection_method: str,
        entity_type: str,
        column: str,
        count: int
    ) -> None:
        """Log protection application.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            protection_method: Method used
            entity_type: Type of entity protected
            column: Column name
            count: Number of protections
        """
        entry = AuditLogEntry(
            event_type='PROTECTION_APPLIED',
            request_id=request_id,
            file_name=file_name,
            status='applied',
            duration_ms=0,
            details={
                'protection_method': protection_method,
                'entity_type': entity_type,
                'column': column,
                'count': count
            }
        )

        self._logger.info(entry.to_json())

        self._record_metric(MetricData(
            name='ProtectionByMethod',
            value=count,
            unit=MetricUnit.COUNT,
            dimensions={'Method': protection_method}
        ))

    def log_error(
        self,
        request_id: str,
        file_name: str,
        error_type: str,
        error_message: str,
        stage: Optional[str] = None
    ) -> None:
        """Log processing error.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            error_type: Type of error
            error_message: Error description
            stage: Pipeline stage where error occurred
        """
        entry = AuditLogEntry(
            event_type='PROCESSING_ERROR',
            request_id=request_id,
            file_name=file_name,
            status='error',
            duration_ms=0,
            details={
                'error_type': error_type,
                'error_message': error_message,
                'stage': stage
            }
        )

        self._logger.error(entry.to_json())

        self._record_metric(MetricData(
            name='ProcessingErrors',
            value=1,
            unit=MetricUnit.COUNT,
            dimensions={'ErrorType': error_type}
        ))

    def log_schema_validation(
        self,
        request_id: str,
        file_name: str,
        is_valid: bool,
        errors: int,
        warnings: int
    ) -> None:
        """Log schema validation results.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            is_valid: Whether schema is preserved
            errors: Number of errors
            warnings: Number of warnings
        """
        entry = AuditLogEntry(
            event_type='SCHEMA_VALIDATION',
            request_id=request_id,
            file_name=file_name,
            status='valid' if is_valid else 'invalid',
            duration_ms=0,
            details={
                'errors': errors,
                'warnings': warnings
            }
        )

        self._logger.info(entry.to_json())

        self._record_metric(MetricData(
            name='SchemaValidation',
            value=1,
            unit=MetricUnit.COUNT,
            dimensions={'Status': 'Valid' if is_valid else 'Invalid'}
        ))

    def _record_metric(self, metric: MetricData) -> None:
        """Record metric to buffer."""
        metric.dimensions.update(self._default_dimensions)
        metric.timestamp = datetime.now(timezone.utc)
        self._metrics_buffer.append(metric)

        if len(self._metrics_buffer) >= self._buffer_size:
            self.flush_metrics()

    def flush_metrics(self) -> None:
        """Flush buffered metrics to CloudWatch."""
        if not self._metrics_buffer:
            return

        if not self._enable_metrics or not self.cloudwatch:
            self._metrics_buffer.clear()
            return

        try:
            metric_data = [m.to_cloudwatch_format() for m in self._metrics_buffer]

            self.cloudwatch.put_metric_data(
                Namespace=self.NAMESPACE,
                MetricData=metric_data
            )

            logger.debug(f"Flushed {len(metric_data)} metrics to CloudWatch")

        except Exception as e:
            logger.warning(f"Failed to publish metrics: {e}")

        finally:
            self._metrics_buffer.clear()

    def create_dashboard_metrics(self) -> dict:
        """Get metrics configuration for CloudWatch dashboard.

        Returns:
            Dashboard widget configuration
        """
        return {
            'widgets': [
                {
                    'type': 'metric',
                    'properties': {
                        'title': 'Processing Volume',
                        'metrics': [
                            [self.NAMESPACE, 'ProcessingStarted'],
                            [self.NAMESPACE, 'ProcessingCompleted']
                        ]
                    }
                },
                {
                    'type': 'metric',
                    'properties': {
                        'title': 'Processing Duration',
                        'metrics': [
                            [self.NAMESPACE, 'ProcessingDuration', {'stat': 'Average'}],
                            [self.NAMESPACE, 'ProcessingDuration', {'stat': 'p99'}]
                        ]
                    }
                },
                {
                    'type': 'metric',
                    'properties': {
                        'title': 'PII Detection',
                        'metrics': [
                            [self.NAMESPACE, 'EntitiesDetected']
                        ]
                    }
                },
                {
                    'type': 'metric',
                    'properties': {
                        'title': 'Errors',
                        'metrics': [
                            [self.NAMESPACE, 'ProcessingErrors']
                        ]
                    }
                }
            ]
        }


_audit_logger: Optional[CloudWatchLogger] = None


def get_audit_logger() -> CloudWatchLogger:
    """Get singleton audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = CloudWatchLogger()
    return _audit_logger
