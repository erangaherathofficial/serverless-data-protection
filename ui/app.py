"""Streamlit demo UI for the serverless data protection framework."""

import os
import streamlit as st
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# `streamlit run ui/app.py` adds only ui/ to sys.path; inject the repo root once.
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.handlers.handler_factory import HandlerFactory, get_handler
from ui import aws_client
from ui.components import (
    decimal_to_native,
    render_status,
    stage_durations_rows,
)

POLICIES_DIR = Path(__file__).resolve().parent.parent / 'policies'


@st.cache_data(show_spinner=False)
def fetch_protected(secure_key: str) -> bytes:
    return aws_client.fetch_protected(secure_key)


def build_raw_key(file_name: str) -> str:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return f"ui/{stamp}-{file_name}"


def list_policies() -> list[Path]:
    if not POLICIES_DIR.exists():
        return []
    return sorted(POLICIES_DIR.glob('*.yaml'))


def render_stack_identity() -> None:
    st.caption(
        f"Region: {os.environ['AWS_REGION']}  |  "
        f"Raw bucket: {os.environ['RAW_BUCKET_NAME']}  |  "
        f"Secure bucket: {os.environ['SECURE_BUCKET_NAME']}  |  "
        f"Audit table: {os.environ['AUDIT_TABLE_NAME']}"
    )


def render_policy_viewer() -> None:
    policies = list_policies()
    if not policies:
        st.info("No local policy files found in policies/.")
        return
    chosen = st.selectbox("Policy", [p.name for p in policies])
    selected = next(p for p in policies if p.name == chosen)
    with st.expander("Policy YAML"):
        st.code(selected.read_text(encoding='utf-8'), language='yaml')
    st.caption(
        "This view shows the local source of truth. The deployed Lambda "
        "runs whatever policy was bundled into the image at deploy time."
    )


def run_pipeline(uploaded_file: Any) -> None:
    file_name: str = uploaded_file.name
    raw_key = build_raw_key(file_name)
    content_type = get_handler(file_name).get_content_type()
    file_bytes: bytes = uploaded_file.getvalue()

    try:
        aws_client.upload_to_raw(file_bytes, raw_key, content_type)
        with st.spinner("Waiting for Lambda to process the file…"):
            audit = aws_client.wait_for_audit(raw_key)
    except Exception as e:
        st.error(str(e))
        return

    if audit is None:
        st.error(
            "Lambda did not produce an audit record within 180s. "
            "Check CloudWatch logs."
        )
        return

    st.session_state['audit'] = decimal_to_native(audit)
    st.session_state['original_bytes'] = file_bytes
    st.session_state['original_filename'] = file_name
    st.rerun()


def render_results() -> None:
    audit: dict = st.session_state['audit']
    original_bytes: bytes = st.session_state['original_bytes']
    file_name: str = st.session_state['original_filename']

    render_status(audit)

    if not audit.get('success'):
        st.error(audit.get('error') or 'Pipeline reported failure.')
        return

    st.subheader("Pipeline stages")
    rows = stage_durations_rows(audit.get('stage_durations') or {})
    st.dataframe(rows, hide_index=True, use_container_width=True)

    detection = audit.get('detection_summary') or {}
    entity_counts = detection.get('entity_counts') or {}
    st.subheader("Detection summary")
    st.metric("Total entities", sum(entity_counts.values()))
    if entity_counts:
        st.bar_chart(entity_counts)
    st.write("Columns with PII:", list(detection.get('columns_with_pii') or []))

    protection = audit.get('protection_summary') or {}
    st.subheader("Protection summary")
    st.metric("Protections applied", protection.get('protections_applied', 0))
    methods_used = protection.get('methods_used') or {}
    if methods_used:
        st.bar_chart(methods_used)

    secure_key = audit.get('secure_key')
    protected_bytes: bytes | None = None
    if secure_key:
        try:
            protected_bytes = fetch_protected(secure_key)
        except Exception as e:
            st.error(str(e))

    st.subheader("Side-by-side preview")
    handler = get_handler(file_name)
    left, right = st.columns(2)
    with left:
        st.caption("Original (first 10 rows)")
        st.dataframe(handler.process(original_bytes, file_name).dataframe.head(10), use_container_width=True)
    with right:
        st.caption("Protected (first 10 rows)")
        if protected_bytes is not None:
            st.dataframe(handler.process(protected_bytes, file_name).dataframe.head(10), use_container_width=True)
        else:
            st.write("Protected output unavailable.")

    with st.expander("Audit record (DynamoDB)"):
        st.json(audit)

    if protected_bytes is not None:
        st.download_button(
            label="Download protected file",
            data=protected_bytes,
            file_name=f"protected_{file_name}",
            mime=handler.get_content_type(),
        )


def main() -> None:
    st.set_page_config(page_title="Serverless Data Protection")
    st.title("Serverless Data Protection")
    st.write(
        "Upload a CSV, JSON, or Parquet file to run it through the deployed "
        "AWS pipeline and inspect the resulting audit record."
    )

    missing = aws_client.validate_env()
    if missing:
        st.error("Missing required environment variables: " + ", ".join(missing))
        st.stop()

    render_stack_identity()
    render_policy_viewer()

    uploaded = st.file_uploader(
        "Upload a file", type=['csv', 'json', 'ndjson', 'parquet']
    )
    if uploaded is not None:
        if not HandlerFactory.is_supported(uploaded.name):
            st.warning(f"Unsupported file: {uploaded.name}")
            return
        if st.button("Run protection pipeline"):
            run_pipeline(uploaded)

    if st.session_state.get('audit'):
        render_results()


if __name__ == "__main__":
    main()
