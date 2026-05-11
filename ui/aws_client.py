"""AWS access for the Streamlit demo UI."""

import os
import time
from typing import Optional

from src.aws.client_manager import get_client_manager

REQUIRED_ENV_VARS: tuple[str, ...] = (
    'AWS_REGION',
    'RAW_BUCKET_NAME',
    'SECURE_BUCKET_NAME',
    'AUDIT_TABLE_NAME',
)


def validate_env() -> list[str]:
    """Return names of required env vars that are missing or empty."""
    return [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]


def upload_to_raw(content: bytes, key: str, content_type: str) -> None:
    """Upload bytes to the configured raw bucket."""
    manager = get_client_manager()
    manager.put_object(manager.raw_bucket, key, content, content_type)


def wait_for_audit(
        raw_key: str,
        timeout_seconds: int = 180,
        poll_interval_seconds: float = 2.0
) -> Optional[dict]:
    """Poll DynamoDB for the audit record produced by the Lambda pipeline."""
    manager = get_client_manager()
    pk = f"FILE#{manager.raw_bucket}/{raw_key}"

    table = manager.dynamodb_resource.Table(manager.audit_table)
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        response = table.query(
            KeyConditionExpression='pk = :pk',
            ExpressionAttributeValues={':pk': pk},
            ScanIndexForward=False,
            Limit=1,
        )
        items = response.get('Items', [])
        if items:
            return items[0]
        time.sleep(poll_interval_seconds)

    return None


def fetch_protected(secure_key: str) -> bytes:
    """Read the protected object from the secure bucket."""
    manager = get_client_manager()
    return manager.get_object(manager.secure_bucket, secure_key)
