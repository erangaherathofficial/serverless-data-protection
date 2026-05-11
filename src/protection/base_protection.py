"""Abstract base class for protection strategies."""

from abc import ABC, abstractmethod
from typing import Optional

from src.policy.policy_parser import ProtectionOptions


class BaseProtection(ABC):
    """Abstract base class for protection strategies.

    Implements the Strategy pattern for different protection techniques.
    Each concrete implementation provides a specific protection method.
    """

    def __init__(self, options: Optional[ProtectionOptions] = None) -> None:
        """Initialize protection strategy.

        Args:
            options: Protection options (uses defaults if None)
        """
        self._options = options or ProtectionOptions()

    @property
    def options(self) -> ProtectionOptions:
        """Get protection options."""
        return self._options

    @property
    @abstractmethod
    def method_name(self) -> str:
        """Get the protection method name."""
        ...

    @property
    @abstractmethod
    def is_reversible(self) -> bool:
        """Whether the protection can be reversed."""
        ...

    @abstractmethod
    def protect(self, value: str) -> str:
        """Apply protection to a value.

        Args:
            value: The value to protect

        Returns:
            Protected value
        """
        ...

    def unprotect(self, value: str) -> str:
        """Reverse the protection if possible.

        Args:
            value: The protected value

        Returns:
            Original value

        Raises:
            NotImplementedError: If protection is not reversible
        """
        if not self.is_reversible:
            raise NotImplementedError(
                f"{self.method_name} protection is not reversible"
            )
        return self._do_unprotect(value)

    def _do_unprotect(self, value: str) -> str:
        """Internal method for reversing protection.

        Override in subclasses that support reversal.
        """
        raise NotImplementedError()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(method={self.method_name})"


class ProtectionRegistry:
    """Registry for protection strategy implementations."""

    _strategies: dict[str, type[BaseProtection]] = {}

    @classmethod
    def register(
            cls, method_name: str, strategy_class: type[BaseProtection]
    ) -> None:
        """Register a protection strategy.

        Args:
            method_name: Name of the protection method
            strategy_class: Strategy class to register
        """
        cls._strategies[method_name] = strategy_class

    @classmethod
    def get(cls, method_name: str,
            options: Optional[ProtectionOptions] = None) -> BaseProtection:
        """Get protection strategy instance.

        Args:
            method_name: Name of the protection method
            options: Protection options

        Returns:
            Configured strategy instance

        Raises:
            KeyError: If method not registered
        """
        if method_name not in cls._strategies:
            raise KeyError(f"Unknown protection method: {method_name}")

        strategy_class = cls._strategies[method_name]
        return strategy_class(options)

    @classmethod
    def get_available_methods(cls) -> list[str]:
        """Get list of registered method names."""
        return list(cls._strategies.keys())

    @classmethod
    def is_registered(cls, method_name: str) -> bool:
        """Check if method is registered."""
        return method_name in cls._strategies


def register_protection(method_name: str):
    """Decorator to register a protection strategy.

    Usage:
        @register_protection('my_method')
        class MyProtection(BaseProtection):
            ...
    """

    def decorator(cls: type[BaseProtection]) -> type[BaseProtection]:
        ProtectionRegistry.register(method_name, cls)
        return cls

    return decorator
