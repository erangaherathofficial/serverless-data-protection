"""Handler factory for file format selection."""

from typing import Type

from src.handlers.base_handler import BaseHandler
from src.handlers.csv_handler import CSVHandler
from src.handlers.json_handler import JSONHandler
from src.handlers.parquet_handler import ParquetHandler


class UnsupportedFormatError(Exception):
    """Raised when file format is not supported."""

    def __init__(self, extension: str):
        self.extension = extension
        super().__init__(f"Unsupported file format: {extension}")


class HandlerFactory:
    """Factory for creating file format handlers.

    Implements the Factory pattern to create appropriate handlers
    based on file extension.
    """

    _handlers: dict[str, Type[BaseHandler]] = {
        '.csv': CSVHandler,
        '.json': JSONHandler,
        '.parquet': ParquetHandler,
    }

    @classmethod
    def get_handler(cls, file_name: str, **kwargs) -> BaseHandler:
        """Get appropriate handler for file.

        Args:
            file_name: File name or path with extension
            **kwargs: Additional arguments passed to handler constructor

        Returns:
            Configured handler instance

        Raises:
            UnsupportedFormatError: If format not supported
        """
        extension = cls._get_extension(file_name)

        if extension not in cls._handlers:
            raise UnsupportedFormatError(extension)

        handler_class = cls._handlers[extension]
        return handler_class(**kwargs)

    @classmethod
    def get_handler_for_extension(
        cls, extension: str, **kwargs
    ) -> BaseHandler:
        """Get handler for specific extension.

        Args:
            extension: File extension (with or without dot)
            **kwargs: Additional arguments passed to handler constructor

        Returns:
            Configured handler instance

        Raises:
            UnsupportedFormatError: If format not supported
        """
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = f'.{ext}'

        if ext not in cls._handlers:
            raise UnsupportedFormatError(ext)

        handler_class = cls._handlers[ext]
        return handler_class(**kwargs)

    @classmethod
    def is_supported(cls, file_name: str) -> bool:
        """Check if file format is supported.

        Args:
            file_name: File name or path

        Returns:
            True if format is supported
        """
        try:
            extension = cls._get_extension(file_name)
            return extension in cls._handlers
        except ValueError:
            return False

    @classmethod
    def get_supported_extensions(cls) -> list[str]:
        """Get list of supported file extensions.

        Returns:
            List of extensions (e.g., ['.csv', '.json', '.parquet'])
        """
        return list(cls._handlers.keys())

    @classmethod
    def register_handler(cls, extension: str,
                         handler_class: Type[BaseHandler]) -> None:
        """Register a new handler for an extension.

        Args:
            extension: File extension (with dot)
            handler_class: Handler class to register
        """
        ext = extension.lower()
        if not ext.startswith('.'):
            ext = f'.{ext}'

        cls._handlers[ext] = handler_class

    @classmethod
    def _get_extension(cls, file_name: str) -> str:
        """Extract lowercase extension from file name.

        Args:
            file_name: File name or path

        Returns:
            Lowercase extension with dot

        Raises:
            ValueError: If no extension found
        """
        if '.' not in file_name:
            raise ValueError(f"No extension found in: {file_name}")

        extension = '.' + file_name.rsplit('.', 1)[-1].lower()
        return extension


def get_handler(file_name: str, **kwargs) -> BaseHandler:
    """Convenience function to get handler for file.

    Args:
        file_name: File name or path with extension
        **kwargs: Additional arguments passed to handler constructor

    Returns:
        Configured handler instance
    """
    return HandlerFactory.get_handler(file_name, **kwargs)
