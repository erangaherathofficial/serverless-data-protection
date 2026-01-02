"""Lambda handler - Main entry point for S3-triggered data protection."""

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import unquote_plus

from src.aws.client_manager import get_client_manager
from src.pipeline.pipeline_orchestrator import PipelineOrchestrator, PipelineResult, create_pipeline

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

_pipeline: Optional[PipelineOrchestrator] = None


class ProcessingError(Exception):
    """Custom exception for processing errors."""

    def __init__(self, message: str, bucket: str = '', key: str = ''):
        super().__init__(message)
        self.bucket = bucket
        self.key = key


def get_pipeline() -> PipelineOrchestrator:
    """Get or create pipeline orchestrator (singleton for Lambda warm starts)."""
    global _pipeline
    if _pipeline is None:
        _pipeline = create_pipeline()
    return _pipeline


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
        event: S3 event notification
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
        records = event.get('Records', [])
        if not records:
            logger.warning("No records found in event")
            return _build_response(200, "No records to process", results, errors)

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
                logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
                errors.append({
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })

    except Exception as e:
        logger.error(f"Handler error: {e}\n{traceback.format_exc()}")
        return _build_response(500, f"Handler error: {str(e)}", results, errors)

    duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
    logger.info(f"Processing completed in {duration_ms:.2f}ms - "
                f"Success: {len(results)}, Errors: {len(errors)}")

    status_code = 200 if not errors else 207
    return _build_response(status_code, "Processing completed", results, errors)


def _process_record(record: dict, request_id: str) -> dict:
    """Process a single S3 event record through the protection pipeline.

    Args:
        record: S3 event record
        request_id: Lambda request ID for tracing

    Returns:
        Processing result for this record
    """
    s3_info = record.get('s3', {})
    bucket = s3_info.get('bucket', {}).get('name', '')
    key = unquote_plus(s3_info.get('object', {}).get('key', ''))

    if not bucket or not key:
        raise ProcessingError("Missing bucket or key in record", bucket, key)

    logger.info(f"Processing file: s3://{bucket}/{key}")

    file_extension = _get_file_extension(key)
    if file_extension not in ('.csv', '.json', '.parquet'):
        raise ProcessingError(
            f"Unsupported file format: {file_extension}",
            bucket, key
        )

    client_manager = get_client_manager()

    try:
        file_content = client_manager.get_object(bucket, key)
        file_size = len(file_content)
        logger.info(f"Downloaded file: {file_size} bytes")
    except Exception as e:
        raise ProcessingError(f"Failed to download file: {e}", bucket, key)

    pipeline = get_pipeline()
    file_name = key.split('/')[-1]

    logger.info(f"Executing protection pipeline for: {file_name}")
    pipeline_result = pipeline.process(file_content, file_name)

    if not pipeline_result.success:
        raise ProcessingError(
            f"Pipeline failed: {pipeline_result.error}",
            bucket, key
        )

    logger.info(f"Pipeline completed in {pipeline_result.total_duration_ms:.2f}ms")

    if pipeline_result.protected_data:
        secure_key = f"protected/{key}"
        content_type = _get_content_type(file_extension)

        try:
            client_manager.put_object(
                client_manager.secure_bucket,
                secure_key,
                pipeline_result.protected_data,
                content_type
            )
            logger.info(
                f"Wrote protected file: s3://{client_manager.secure_bucket}/{secure_key}"
            )
        except Exception as e:
            raise ProcessingError(f"Failed to write protected file: {e}", bucket, key)
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
        'detection': pipeline_result.detection_summary,
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
        'detection_summary': pipeline_result.detection_summary,
        'protection_summary': pipeline_result.protection_summary,
        'stage_durations': {
            sr.stage.value: sr.duration_ms
            for sr in pipeline_result.stage_results
        },
        'error': pipeline_result.error,
        'ttl': int((datetime.now(timezone.utc).timestamp()) + (90 * 24 * 60 * 60))
    }


def _get_file_extension(key: str) -> str:
    """Extract file extension from S3 key."""
    if '.' in key:
        return '.' + key.rsplit('.', 1)[-1].lower()
    return ''


def _get_content_type(extension: str) -> str:
    """Get content type for file extension."""
    content_types = {
        '.csv': 'text/csv',
        '.json': 'application/json',
        '.parquet': 'application/octet-stream'
    }
    return content_types.get(extension, 'application/octet-stream')


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
