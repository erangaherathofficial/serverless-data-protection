"""Handler factory for file format selection."""

from typing import Optional

from src.handlers.base_handler import BaseHandler
from src.handlers.csv_handler import CSVHandler
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler


class UnsupportedFormatError(Exception):
    """Raised when file format is not supported."""

    def __init__(self, extension: str) -> None:
        self.extension = extension
        super().__init__(f"Unsupported file format: {extension}")


class HandlerFactory:
    """Factory for creating file-format handlers based on extension."""

    _handlers: dict[str, type[BaseHandler]] = {
        '.csv': CSVHandler,
        '.json': JSONHandler,
        '.ndjson': JSONHandler,
        '.parquet': ParquetHandler,
    }

    @classmethod
    def get_handler(cls, file_name: str, **kwargs) -> BaseHandler:
        """Return a configured handler for ``file_name``."""
        extension = cls._get_extension(file_name)
        handler_class = cls._handlers.get(extension)
        if handler_class is None:
            raise UnsupportedFormatError(extension or file_name)
        return handler_class(**kwargs)

    @classmethod
    def is_supported(cls, file_name: str) -> bool:
        """Return ``True`` if ``file_name`` ends with a supported extension."""
        return cls._get_extension(file_name) in cls._handlers

    @classmethod
    def format_name(cls, file_name: str) -> str:
        """Return the upper-case extension (without dot) for display."""
        extension = cls._get_extension(file_name)
        return extension[1:].upper() if extension else 'UNKNOWN'

    @classmethod
    def _get_extension(cls, file_name: str) -> Optional[str]:
        if '.' not in file_name:
            return None
        return '.' + file_name.rsplit('.', 1)[-1].lower()


def get_handler(file_name: str, **kwargs) -> BaseHandler:
    """Convenience function — see :meth:`HandlerFactory.get_handler`."""
    return HandlerFactory.get_handler(file_name, **kwargs)
