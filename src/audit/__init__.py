"""Audit trail package."""

from src.audit.cloudwatch_logger import (
    AuditLogEntry,
    CloudWatchLogger,
    MetricData,
    MetricUnit,
    get_audit_logger,
)
from src.audit.dynamodb_writer import (
    DetectionRecord,
    DynamoDBWriter,
    EntityRecord,
    ProcessingRecord,
    ProtectionRecord,
    get_audit_writer,
)

__all__ = [
    'CloudWatchLogger',
    'AuditLogEntry',
    'MetricData',
    'MetricUnit',
    'get_audit_logger',
    'DynamoDBWriter',
    'ProcessingRecord',
    'DetectionRecord',
    'ProtectionRecord',
    'EntityRecord',
    'get_audit_writer',
]
