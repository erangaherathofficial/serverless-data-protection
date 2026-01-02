"""DynamoDB audit record writer."""

import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProcessingRecord:
    """Audit record for file processing activity."""

    pk: str
    sk: str
    request_id: str
    source_bucket: str
    source_key: str
    file_format: str
    file_size: int
    success: bool
    duration_ms: int
    timestamp: str
    gsi1pk: str = ''
    gsi1sk: str = ''
    secure_bucket: Optional[str] = None
    secure_key: Optional[str] = None
    error: Optional[str] = None
    ttl: Optional[int] = None

    def __post_init__(self):
        if not self.gsi1pk:
            self.gsi1pk = f"DATE#{self.timestamp[:10]}"
        if not self.gsi1sk:
            file_name = self.source_key.split('/')[-1]
            self.gsi1sk = f"FILE#{file_name}"


@dataclass
class DetectionRecord:
    """Audit record for PII detection results."""

    pk: str
    sk: str
    request_id: str
    file_name: str
    timestamp: str
    total_entities: int
    entity_types: dict[str, int]
    columns_with_pii: list[str]
    cells_scanned: int
    cells_with_pii: int
    detection_duration_ms: int
    gsi1pk: str = ''
    gsi1sk: str = ''
    ttl: Optional[int] = None

    def __post_init__(self):
        if not self.gsi1pk:
            self.gsi1pk = f"DATE#{self.timestamp[:10]}"
        if not self.gsi1sk:
            self.gsi1sk = f"DETECTION#{self.timestamp}"


@dataclass
class ProtectionRecord:
    """Audit record for protection actions."""

    pk: str
    sk: str
    request_id: str
    file_name: str
    timestamp: str
    protections_applied: int
    methods_used: dict[str, int]
    protection_duration_ms: int
    gsi1pk: str = ''
    gsi1sk: str = ''
    ttl: Optional[int] = None

    def __post_init__(self):
        if not self.gsi1pk:
            self.gsi1pk = f"DATE#{self.timestamp[:10]}"
        if not self.gsi1sk:
            self.gsi1sk = f"PROTECTION#{self.timestamp}"


@dataclass
class EntityRecord:
    """Audit record for individual detected entity."""

    pk: str
    sk: str
    request_id: str
    file_name: str
    entity_type: str
    column_name: str
    row_index: int
    protection_method: str
    confidence_score: float
    timestamp: str
    ttl: Optional[int] = None


class DynamoDBWriter:
    """Writer for DynamoDB audit records.

    Stores audit trail with support for:
    - Processing activities
    - Detection results
    - Protection actions
    - Entity-level details
    """

    DEFAULT_TTL_DAYS = 90

    def __init__(
        self,
        table_name: Optional[str] = None,
        ttl_days: int = DEFAULT_TTL_DAYS
    ) -> None:
        """Initialize DynamoDB writer.

        Args:
            table_name: DynamoDB table name
            ttl_days: Days until records expire
        """
        self._table_name = table_name or os.environ.get('AUDIT_TABLE_NAME', '')
        self._ttl_days = ttl_days
        self._table = None

    @property
    def table(self):
        """Get DynamoDB table resource (lazy initialization)."""
        if self._table is None and self._table_name:
            try:
                from src.aws.client_manager import get_client_manager
                client_manager = get_client_manager()
                self._table = client_manager.dynamodb_resource.Table(self._table_name)
            except Exception as e:
                logger.warning(f"Failed to get DynamoDB table: {e}")
        return self._table

    def write_processing_record(
        self,
        request_id: str,
        source_bucket: str,
        source_key: str,
        file_format: str,
        file_size: int,
        success: bool,
        duration_ms: float,
        secure_bucket: Optional[str] = None,
        secure_key: Optional[str] = None,
        error: Optional[str] = None
    ) -> Optional[str]:
        """Write processing activity record.

        Args:
            request_id: Lambda request ID
            source_bucket: Source S3 bucket
            source_key: Source S3 key
            file_format: File format
            file_size: File size in bytes
            success: Processing success
            duration_ms: Processing duration
            secure_bucket: Destination bucket
            secure_key: Destination key
            error: Error message if failed

        Returns:
            Record ID or None if write failed
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        record = ProcessingRecord(
            pk=f"FILE#{source_bucket}/{source_key}",
            sk=f"PROCESS#{timestamp}",
            request_id=request_id,
            source_bucket=source_bucket,
            source_key=source_key,
            file_format=file_format,
            file_size=file_size,
            success=success,
            duration_ms=int(duration_ms),
            timestamp=timestamp,
            secure_bucket=secure_bucket,
            secure_key=secure_key,
            error=error,
            ttl=self._calculate_ttl()
        )

        return self._write_record(record)

    def write_detection_record(
        self,
        request_id: str,
        file_name: str,
        total_entities: int,
        entity_types: dict[str, int],
        columns_with_pii: list[str],
        cells_scanned: int,
        cells_with_pii: int,
        duration_ms: float
    ) -> Optional[str]:
        """Write PII detection record.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            total_entities: Total entities found
            entity_types: Count by entity type
            columns_with_pii: Columns with PII
            cells_scanned: Total cells scanned
            cells_with_pii: Cells containing PII
            duration_ms: Detection duration

        Returns:
            Record ID or None if write failed
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        record = DetectionRecord(
            pk=f"FILE#{file_name}",
            sk=f"DETECTION#{timestamp}",
            request_id=request_id,
            file_name=file_name,
            timestamp=timestamp,
            total_entities=total_entities,
            entity_types=entity_types,
            columns_with_pii=columns_with_pii,
            cells_scanned=cells_scanned,
            cells_with_pii=cells_with_pii,
            detection_duration_ms=int(duration_ms),
            ttl=self._calculate_ttl()
        )

        return self._write_record(record)

    def write_protection_record(
        self,
        request_id: str,
        file_name: str,
        protections_applied: int,
        methods_used: dict[str, int],
        duration_ms: float
    ) -> Optional[str]:
        """Write protection action record.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            protections_applied: Total protections
            methods_used: Count by method
            duration_ms: Protection duration

        Returns:
            Record ID or None if write failed
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        record = ProtectionRecord(
            pk=f"FILE#{file_name}",
            sk=f"PROTECTION#{timestamp}",
            request_id=request_id,
            file_name=file_name,
            timestamp=timestamp,
            protections_applied=protections_applied,
            methods_used=methods_used,
            protection_duration_ms=int(duration_ms),
            ttl=self._calculate_ttl()
        )

        return self._write_record(record)

    def write_entity_records(
        self,
        request_id: str,
        file_name: str,
        entities: list[dict]
    ) -> int:
        """Write individual entity records.

        Args:
            request_id: Lambda request ID
            file_name: Source file name
            entities: List of entity details

        Returns:
            Number of records written
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        written = 0

        for i, entity in enumerate(entities):
            record = EntityRecord(
                pk=f"FILE#{file_name}",
                sk=f"ENTITY#{timestamp}#{i:05d}",
                request_id=request_id,
                file_name=file_name,
                entity_type=entity.get('entity_type', ''),
                column_name=entity.get('column_name', ''),
                row_index=entity.get('row_index', 0),
                protection_method=entity.get('protection_method', ''),
                confidence_score=entity.get('score', 0.0),
                timestamp=timestamp,
                ttl=self._calculate_ttl()
            )

            if self._write_record(record):
                written += 1

        return written

    def query_by_file(
        self,
        bucket: str,
        key: str,
        limit: int = 100
    ) -> list[dict]:
        """Query records for a specific file.

        Args:
            bucket: S3 bucket
            key: S3 key
            limit: Maximum records to return

        Returns:
            List of matching records
        """
        if not self.table:
            return []

        try:
            response = self.table.query(
                KeyConditionExpression='pk = :pk',
                ExpressionAttributeValues={':pk': f"FILE#{bucket}/{key}"},
                Limit=limit,
                ScanIndexForward=False
            )
            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def query_by_date(
        self,
        date: str,
        limit: int = 100
    ) -> list[dict]:
        """Query records for a specific date.

        Args:
            date: Date in YYYY-MM-DD format
            limit: Maximum records to return

        Returns:
            List of matching records
        """
        if not self.table:
            return []

        try:
            response = self.table.query(
                IndexName='gsi1',
                KeyConditionExpression='gsi1pk = :pk',
                ExpressionAttributeValues={':pk': f"DATE#{date}"},
                Limit=limit,
                ScanIndexForward=False
            )
            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def get_processing_stats(self, days: int = 7) -> dict:
        """Get processing statistics for recent days.

        Args:
            days: Number of days to include

        Returns:
            Statistics dictionary
        """
        stats = {
            'total_files': 0,
            'successful': 0,
            'failed': 0,
            'total_entities': 0,
            'by_format': {},
            'by_date': {}
        }

        from datetime import timedelta

        for i in range(days):
            date = (datetime.now(timezone.utc) - timedelta(days=i)).strftime('%Y-%m-%d')
            records = self.query_by_date(date)

            for record in records:
                if record.get('sk', '').startswith('PROCESS#'):
                    stats['total_files'] += 1
                    if record.get('success'):
                        stats['successful'] += 1
                    else:
                        stats['failed'] += 1

                    fmt = record.get('file_format', 'UNKNOWN')
                    stats['by_format'][fmt] = stats['by_format'].get(fmt, 0) + 1

                    if date not in stats['by_date']:
                        stats['by_date'][date] = 0
                    stats['by_date'][date] += 1

        return stats

    def _write_record(self, record: Any) -> Optional[str]:
        """Write record to DynamoDB.

        Args:
            record: Dataclass record to write

        Returns:
            Record key or None if failed
        """
        if not self.table:
            logger.warning("DynamoDB table not configured")
            return None

        try:
            item = self._convert_to_dynamodb_item(asdict(record))
            self.table.put_item(Item=item)
            return f"{record.pk}#{record.sk}"

        except Exception as e:
            logger.error(f"Failed to write record: {e}")
            return None

    def _convert_to_dynamodb_item(self, item: dict) -> dict:
        """Convert item for DynamoDB compatibility.

        Handles float to Decimal conversion and removes None values.
        """
        result = {}

        for key, value in item.items():
            if value is None:
                continue

            if isinstance(value, float):
                result[key] = Decimal(str(value))
            elif isinstance(value, dict):
                result[key] = self._convert_to_dynamodb_item(value)
            elif isinstance(value, list):
                result[key] = [
                    self._convert_to_dynamodb_item(v) if isinstance(v, dict)
                    else Decimal(str(v)) if isinstance(v, float)
                    else v
                    for v in value
                ]
            else:
                result[key] = value

        return result

    def _calculate_ttl(self) -> int:
        """Calculate TTL timestamp."""
        return int(datetime.now(timezone.utc).timestamp()) + (self._ttl_days * 24 * 60 * 60)


_audit_writer: Optional[DynamoDBWriter] = None


def get_audit_writer() -> DynamoDBWriter:
    """Get singleton audit writer instance."""
    global _audit_writer
    if _audit_writer is None:
        _audit_writer = DynamoDBWriter()
    return _audit_writer
