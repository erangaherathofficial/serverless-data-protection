"""Render helpers for the Streamlit demo UI."""

import streamlit as st
from decimal import Decimal
from typing import Any

STAGE_ORDER: tuple[str, ...] = (
    'receive', 'validate', 'detect', 'evaluate',
    'protect', 'schema_check', 'output',
)


def decimal_to_native(value: Any) -> Any:
    """Recursively convert ``Decimal`` values to ``int`` or ``float``."""
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, dict):
        return {k: decimal_to_native(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decimal_to_native(v) for v in value]
    if isinstance(value, set):
        return [decimal_to_native(v) for v in value]
    return value


def stage_durations_rows(stage_durations: dict) -> list[dict]:
    """Order stage durations for tabular display."""
    rows: list[dict] = []
    for stage in STAGE_ORDER:
        if stage in stage_durations:
            rows.append({
                'stage': stage,
                'duration_ms': decimal_to_native(stage_durations[stage]),
            })
    return rows


def render_status(audit: dict) -> None:
    """Render the four-column run status header."""
    cols = st.columns(4)
    success = bool(audit.get('success'))
    cols[0].metric('Status', 'Success' if success else 'Failed')
    cols[1].metric('Duration (ms)', decimal_to_native(audit.get('duration_ms', 0)))
    cols[2].metric('Format', str(audit.get('file_format', '')))
    cols[3].metric('Request ID', str(audit.get('request_id', '')))
