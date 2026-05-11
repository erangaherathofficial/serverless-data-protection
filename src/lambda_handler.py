"""Lambda handler - Main entry point for S3-triggered data protection."""

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional
from urllib.parse import unquote_plus

from src.aws.client_manager import get_client_manager
from src.handlers.handler_factory import HandlerFactory, get_handler
from src.pipeline.pipeline_orchestrator import (
    PipelineOrchestrator,
    PipelineResult,
    create_pipeline,
)

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

_pipeline: Optional[PipelineOrchestrator] = None


class ProcessingError(Exception):
    """Custom exception for processing errors."""

    def __init__(self, message: str, bucket: str = '', key: str = '') -> None:
        super().__init__(message)
        self.bucket = bucket
        self.key = key


def get_pipeline() -> PipelineOrchestrator:
    """Get or create pipeline orchestrator.

    Uses singleton pattern for Lambda warm starts.
    """
    global _pipeline
    if _pipeline is None:
        _pipeline = create_pipeline()
    return _pipeline


def _normalize_event(event: dict) -> list[dict]:
    """Normalize S3 or EventBridge events to flat ``{bucket, key}`` records.

    Direct S3 event notifications URL-encode the object key; EventBridge S3
    events deliver the key already decoded. ``unquote_plus`` is therefore
    applied only on the Records path so a literal ``+`` in an EventBridge key
    is not silently decoded to a space.
    """
    if 'Records' in event:
        return [
            {
                'bucket': r['s3']['bucket']['name'],
                'key': unquote_plus(r['s3']['object']['key']),
            }
            for r in event['Records']
        ]

    if event.get('source') == 'aws.s3' and 'detail' in event:
        detail = event['detail']
        bucket_name = detail.get('bucket', {}).get('name', '')
        object_key = detail.get('object', {}).get('key', '')

        if bucket_name and object_key:
            return [{'bucket': bucket_name, 'key': object_key}]

    logger.warning(f"Unknown event format: {list(event.keys())}")
    return []


def handler(event: dict, context: Any) -> dict:
    """Lambda handler for S3-triggered data protection processing.

    Implements the 7-step processing pipeline:
    1. S3 upload triggers Lambda (this handler)
    2. File format validation
    3. Presidio scans for PII
    4. Policy engine generates protection plan
    5. Protection modules apply transformations
    6. Protected data written to secure S3 bucket
    7. Audit trail generated

    Args:
        event: S3 event notification or EventBridge event
        context: Lambda context object

    Returns:
        Processing result with status and details
    """
    start_time = datetime.now(timezone.utc)
    request_id = context.aws_request_id if context else 'local-test'

    logger.info(f"Processing started - Request ID: {request_id}")

    results = []
    errors = []

    try:
        records = _normalize_event(event)
        if not records:
            logger.warning("No records found in event")
            return _build_response(
                200, "No records to process", results, errors
            )

        for record in records:
            try:
                result = _process_record(record, request_id)
                results.append(result)
            except ProcessingError as e:
                logger.error(f"Processing error: {e}")
                errors.append({
                    'bucket': e.bucket,
                    'key': e.key,
                    'error': str(e)
                })
            except Exception as e:
                tb = traceback.format_exc()
                logger.error(f"Unexpected error: {e}\n{tb}")
                errors.append({'error': str(e)})

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Handler error: {e}\n{tb}")
        msg = f"Handler error: {str(e)}"
        return _build_response(500, msg, results, errors)

    elapsed = datetime.now(timezone.utc) - start_time
    duration_ms = elapsed.total_seconds() * 1000
    logger.info(
        f"Processing completed in {duration_ms:.2f}ms - "
        f"Success: {len(results)}, Errors: {len(errors)}"
    )

    status_code = 200 if not errors else 207
    return _build_response(
        status_code, "Processing completed", results, errors
    )


def _process_record(record: dict, request_id: str) -> dict:
    """Process a single normalized record through the protection pipeline.

    Args:
        record: Normalized record (``{bucket, key}`` from ``_normalize_event``)
        request_id: Lambda request ID for tracing

    Returns:
        Processing result for this record
    """
    bucket = record.get('bucket', '')
    key = record.get('key', '')

    if not bucket or not key:
        raise ProcessingError("Missing bucket or key in record", bucket, key)

    logger.info(f"Processing file: s3://{bucket}/{key}")

    if not HandlerFactory.is_supported(key):
        raise ProcessingError(
            f"Unsupported file format: {key}",
            bucket, key
        )

    client_manager = get_client_manager()

    try:
        file_content = client_manager.get_object(bucket, key)
        file_size = len(file_content)
        logger.info(f"Downloaded file: {file_size} bytes")
    except Exception as e:
        raise ProcessingError(
            f"Failed to download file: {e}", bucket, key
        ) from e

    pipeline = get_pipeline()
    file_name = key.split('/')[-1]

    logger.info(f"Executing protection pipeline for: {file_name}")
    pipeline_result = pipeline.process(file_content, file_name)

    if not pipeline_result.success:
        raise ProcessingError(
            f"Pipeline failed: {pipeline_result.error}",
            bucket, key
        )

    duration = pipeline_result.total_duration_ms
    logger.info(f"Pipeline completed in {duration:.2f}ms")

    if pipeline_result.protected_data:
        secure_key = f"protected/{key}"
        content_type = get_handler(file_name).get_content_type()

        try:
            client_manager.put_object(
                client_manager.secure_bucket,
                secure_key,
                pipeline_result.protected_data,
                content_type
            )
            bucket_name = client_manager.secure_bucket
            logger.info(
                f"Wrote protected file: s3://{bucket_name}/{secure_key}"
            )
        except Exception as e:
            raise ProcessingError(
                f"Failed to write protected file: {e}", bucket, key
            ) from e
    else:
        secure_key = None
        logger.warning("No protected data generated")

    audit_record = _create_audit_record(
        request_id, bucket, key, secure_key, pipeline_result
    )

    try:
        if client_manager.audit_table:
            client_manager.put_audit_record(audit_record)
            logger.info(f"Audit record created: {audit_record['pk']}")
    except Exception as e:
        logger.warning(f"Failed to write audit record: {e}")

    return {
        'source': {
            'bucket': bucket,
            'key': key,
            'size': file_size
        },
        'destination': {
            'bucket': client_manager.secure_bucket,
            'key': secure_key
        } if secure_key else None,
        'pipeline': {
            'success': pipeline_result.success,
            'duration_ms': pipeline_result.total_duration_ms,
            'stages': [
                {
                    'name': sr.stage.value,
                    'success': sr.success,
                    'duration_ms': sr.duration_ms
                }
                for sr in pipeline_result.stage_results
            ]
        },
        'detection': _strip_entities(pipeline_result.detection_summary),
        'protection': pipeline_result.protection_summary,
        'status': 'success',
        'request_id': request_id
    }


def _create_audit_record(
        request_id: str,
        source_bucket: str,
        source_key: str,
        secure_key: Optional[str],
        pipeline_result: PipelineResult
) -> dict:
    """Create audit record for DynamoDB.

    Args:
        request_id: Lambda request ID
        source_bucket: Source S3 bucket
        source_key: Source S3 key
        secure_key: Protected file S3 key
        pipeline_result: Pipeline execution result

    Returns:
        Audit record dictionary
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    file_name = source_key.split('/')[-1]

    return {
        'pk': f"FILE#{source_bucket}/{source_key}",
        'sk': f"PROCESS#{timestamp}",
        'gsi1pk': f"DATE#{timestamp[:10]}",
        'gsi1sk': f"FILE#{file_name}",
        'request_id': request_id,
        'source_bucket': source_bucket,
        'source_key': source_key,
        'secure_key': secure_key,
        'file_format': pipeline_result.file_format,
        'success': pipeline_result.success,
        'duration_ms': int(pipeline_result.total_duration_ms),
        'timestamp': timestamp,
        'detection_summary': _sanitize_for_dynamodb(
            _strip_entities(pipeline_result.detection_summary)
        ),
        'protection_summary': _sanitize_for_dynamodb(
            pipeline_result.protection_summary
        ),
        'stage_durations': {
            sr.stage.value: int(sr.duration_ms)
            for sr in pipeline_result.stage_results
        },
        'error': pipeline_result.error,
        'ttl': int(datetime.now(timezone.utc).timestamp()) + (90 * 86400)
    }


def _strip_entities(summary: Optional[dict]) -> Optional[dict]:
    """Drop the raw `entities` list so PII is not persisted to the audit log."""
    if not summary:
        return summary
    return {k: v for k, v in summary.items() if k != 'entities'}


def _sanitize_for_dynamodb(obj: Any) -> Any:
    """Convert floats to Decimal for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: _sanitize_for_dynamodb(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_for_dynamodb(item) for item in obj]
    return obj


def _build_response(status_code: int, message: str,
                    results: list, errors: list) -> dict:
    """Build standardized Lambda response."""
    return {
        'statusCode': status_code,
        'body': json.dumps({
            'message': message,
            'processed': len(results),
            'failed': len(errors),
            'results': results,
            'errors': errors
        })
    }
