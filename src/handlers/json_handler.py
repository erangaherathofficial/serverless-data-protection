"""JSON file handler implementation."""

import json
import pandas as pd
from typing import Any, Optional

from src.handlers.base_handler import BaseHandler


class JSONHandler(BaseHandler):
    """Handler for JSON file format processing.

    Supports:
    - Array of objects: [{"a": 1}, {"a": 2}]
    - Object with records array: {"records": [{"a": 1}]}
    - Newline-delimited JSON (NDJSON): {"a": 1}\n{"a": 2}
    """

    def __init__(self, encoding: str = 'utf-8',
                 records_path: Optional[str] = None) -> None:
        super().__init__()
        self._encoding = encoding
        self._records_path = records_path
        self._detected_format: Optional[str] = None
        self._detected_path: Optional[str] = None

    @property
    def detected_format(self) -> Optional[str]:
        """Get detected JSON format type."""
        return self._detected_format

    @property
    def records_path(self) -> Optional[str]:
        """Get path to records array in JSON structure."""
        return self._detected_path or self._records_path

    def validate(self, content: bytes, file_name: str) -> bool:
        """Validate JSON content.

        Checks:
        - File is not empty
        - Content is valid JSON
        - Contains parseable records

        Args:
            content: Raw JSON bytes
            file_name: Original file name

        Returns:
            True if valid JSON with records
        """
        if not content or len(content.strip()) == 0:
            self._add_validation_error("File is empty")
            return False

        try:
            text = content.decode(self._encoding)
        except UnicodeDecodeError as e:
            self._add_validation_error(f"Invalid encoding: {e}")
            return False

        text = text.strip()

        has_newlines = '\n' in text
        not_array_or_object = (
                not text.startswith('[') and not text.startswith('{')
        )
        if has_newlines and not_array_or_object:
            return self._validate_ndjson(text)

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            if has_newlines:
                return self._validate_ndjson(text)
            self._add_validation_error(f"Invalid JSON: {e}")
            return False

        if isinstance(data, list):
            return self._validate_array(data)
        elif isinstance(data, dict):
            return self._validate_object(data)
        else:
            self._add_validation_error("JSON must be an array or object")
            return False

    def _validate_ndjson(self, text: str) -> bool:
        """Validate newline-delimited JSON."""
        lines = [line.strip() for line in text.split('\n') if line.strip()]

        if not lines:
            self._add_validation_error("No JSON lines found")
            return False

        for i, line in enumerate(lines, start=1):
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    msg = f"Line {i} is not a JSON object"
                    self._add_validation_error(msg)
                    return False
            except json.JSONDecodeError as e:
                self._add_validation_error(f"Line {i} invalid JSON: {e}")
                return False

        self._detected_format = 'ndjson'
        return True

    def _validate_array(self, data: list) -> bool:
        """Validate JSON array format."""
        if not data:
            self._add_validation_error("Empty JSON array")
            return False

        if not all(isinstance(item, dict) for item in data):
            self._add_validation_error("Array must contain only objects")
            return False

        self._detected_format = 'array'
        return True

    def _validate_object(self, data: dict) -> bool:
        """Validate JSON object format and find records array."""
        if self._records_path:
            records = self._get_nested_value(data, self._records_path)
            if records is None:
                self._add_validation_error(
                    f"Path '{self._records_path}' not found in JSON"
                )
                return False
            if not isinstance(records, list):
                self._add_validation_error(
                    f"Path '{self._records_path}' is not an array"
                )
                return False
            self._detected_path = self._records_path
            self._detected_format = 'nested'
            return True

        for key in ['records', 'data', 'items', 'results', 'rows']:
            if key in data and isinstance(data[key], list):
                all_dicts = all(isinstance(item, dict) for item in data[key])
                if data[key] and all_dicts:
                    self._detected_path = key
                    self._detected_format = 'nested'
                    return True

        for key, value in data.items():
            if isinstance(value, list) and value:
                if all(isinstance(item, dict) for item in value):
                    self._detected_path = key
                    self._detected_format = 'nested'
                    return True

        self._add_validation_error(
            "No records array found. Specify records_path or use array format"
        )
        return False

    def parse(self, content: bytes) -> pd.DataFrame:
        """Parse JSON content into DataFrame.

        Args:
            content: Raw JSON bytes

        Returns:
            Parsed DataFrame
        """
        text = content.decode(self._encoding).strip()

        if self._detected_format == 'ndjson':
            return self._parse_ndjson(text)

        data = json.loads(text)

        if self._detected_format == 'array':
            records = data
        else:
            records = self._get_nested_value(data, self._detected_path)

        df = pd.json_normalize(records)
        df = df.astype(str)
        df = df.replace('nan', '')

        return df

    def _parse_ndjson(self, text: str) -> pd.DataFrame:
        """Parse newline-delimited JSON."""
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        records = [json.loads(line) for line in lines]

        df = pd.json_normalize(records)
        df = df.astype(str)
        df = df.replace('nan', '')

        return df

    def serialize(self, df: pd.DataFrame) -> bytes:
        """Serialize DataFrame to JSON bytes.

        Args:
            df: DataFrame to serialize

        Returns:
            JSON bytes
        """
        records = df.to_dict(orient='records')

        if self._detected_format == 'ndjson':
            lines = [
                json.dumps(record, ensure_ascii=False) for record in records
            ]
            content = '\n'.join(lines)
        elif self._detected_format == 'nested' and self._detected_path:
            content = json.dumps(
                {self._detected_path: records},
                indent=2,
                ensure_ascii=False
            )
        else:
            content = json.dumps(records, indent=2, ensure_ascii=False)

        return content.encode(self._encoding)

    def get_content_type(self) -> str:
        """Get MIME content type for JSON."""
        return 'application/json'

    def _get_format_name(self) -> str:
        """Get format name."""
        return 'JSON'

    def _get_nested_value(self, data: dict, path: str) -> Any:
        """Get nested value from dict using dot notation.

        Args:
            data: Source dictionary
            path: Dot-separated path (e.g., 'response.data.records')

        Returns:
            Value at path or None if not found
        """
        keys = path.split('.')
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current
