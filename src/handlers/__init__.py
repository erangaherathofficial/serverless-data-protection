"""File handlers package."""

from src.handlers.base_handler import BaseHandler, FileMetadata, ProcessedData
from src.handlers.csv_handler import CSVHandler
from src.handlers.handler_factory import (
    HandlerFactory,
    UnsupportedFormatError,
    get_handler,
)
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler

__all__ = [
    'BaseHandler',
    'FileMetadata',
    'ProcessedData',
    'CSVHandler',
    'JSONHandler',
    'ParquetHandler',
    'HandlerFactory',
    'UnsupportedFormatError',
    'get_handler',
]
