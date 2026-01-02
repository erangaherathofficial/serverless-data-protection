"""YAML policy configuration parser."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

import yaml

logger = logging.getLogger(__name__)


class PolicyValidationError(Exception):
    """Raised when policy validation fails."""

    def __init__(self, message: str, errors: Optional[list[str]] = None):
        super().__init__(message)
        self.errors = errors or []


@dataclass
class ProtectionOptions:
    """Options for a protection method."""

    mask_char: str = '*'
    visible_chars: int = 4
    direction: str = 'right'
    preserve_length: bool = True
    token_prefix: str = 'TOK_'
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> 'ProtectionOptions':
        """Create from dictionary."""
        if not data:
            return cls()

        return cls(
            mask_char=data.get('mask_char', '*'),
            visible_chars=data.get('visible_chars', 4),
            direction=data.get('direction', 'right'),
            preserve_length=data.get('preserve_length', True),
            token_prefix=data.get('token_prefix', 'TOK_'),
            extra={k: v for k, v in data.items()
                   if k not in ['mask_char', 'visible_chars', 'direction',
                                'preserve_length', 'token_prefix']}
        )


@dataclass
class ProtectionRule:
    """A single protection rule from policy."""

    entity_type: str
    protection_method: str
    priority: int = 1
    description: str = ''
    options: ProtectionOptions = field(default_factory=ProtectionOptions)
    conditions: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> 'ProtectionRule':
        """Create rule from dictionary."""
        return cls(
            entity_type=data['entity_type'],
            protection_method=data['protection_method'],
            priority=data.get('priority', 1),
            description=data.get('description', ''),
            options=ProtectionOptions.from_dict(data.get('options')),
            conditions=data.get('conditions', {})
        )


@dataclass
class PolicySettings:
    """Global policy settings."""

    default_protection: str = 'masking'
    confidence_threshold: float = 0.7
    preserve_schema: bool = True
    fail_on_error: bool = False
    log_detections: bool = True
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> 'PolicySettings':
        """Create from dictionary."""
        if not data:
            return cls()

        return cls(
            default_protection=data.get('default_protection', 'masking'),
            confidence_threshold=data.get('confidence_threshold', 0.7),
            preserve_schema=data.get('preserve_schema', True),
            fail_on_error=data.get('fail_on_error', False),
            log_detections=data.get('log_detections', True),
            extra={k: v for k, v in data.items()
                   if k not in ['default_protection', 'confidence_threshold',
                                'preserve_schema', 'fail_on_error', 'log_detections']}
        )


@dataclass
class Policy:
    """Parsed protection policy."""

    version: str
    description: str
    settings: PolicySettings
    rules: list[ProtectionRule]
    metadata: dict = field(default_factory=dict)

    def get_rule_for_entity(self, entity_type: str) -> Optional[ProtectionRule]:
        """Get highest priority rule for entity type."""
        matching = [r for r in self.rules if r.entity_type == entity_type]
        if not matching:
            return None
        return min(matching, key=lambda r: r.priority)

    def get_rules_by_method(self, method: str) -> list[ProtectionRule]:
        """Get all rules using a specific protection method."""
        return [r for r in self.rules if r.protection_method == method]

    def get_entity_types(self) -> set[str]:
        """Get all entity types covered by rules."""
        return {r.entity_type for r in self.rules}

    def to_dict(self) -> dict:
        """Convert policy to dictionary."""
        return {
            'version': self.version,
            'description': self.description,
            'settings': {
                'default_protection': self.settings.default_protection,
                'confidence_threshold': self.settings.confidence_threshold,
                'preserve_schema': self.settings.preserve_schema,
                'fail_on_error': self.settings.fail_on_error,
                'log_detections': self.settings.log_detections,
                **self.settings.extra
            },
            'rules': [
                {
                    'entity_type': r.entity_type,
                    'protection_method': r.protection_method,
                    'priority': r.priority,
                    'description': r.description,
                    'options': {
                        'mask_char': r.options.mask_char,
                        'visible_chars': r.options.visible_chars,
                        'direction': r.options.direction,
                        **r.options.extra
                    } if r.options else {}
                }
                for r in self.rules
            ],
            'metadata': self.metadata
        }


class PolicyParser:
    """Parser for YAML protection policies."""

    VALID_PROTECTION_METHODS = [
        'aes256_encrypt',
        'sha256_hash',
        'masking',
        'tokenization',
        'redact',
        'none'
    ]

    VALID_DIRECTIONS = ['left', 'right', 'center']

    def __init__(self, policy_dir: Optional[str] = None) -> None:
        """Initialize parser.

        Args:
            policy_dir: Directory containing policy files
        """
        self._policy_dir = policy_dir or self._get_default_policy_dir()
        self._validation_errors: list[str] = []

    @property
    def validation_errors(self) -> list[str]:
        """Get validation errors from last parse."""
        return self._validation_errors.copy()

    def parse_file(self, file_path: Union[str, Path]) -> Policy:
        """Parse policy from YAML file.

        Args:
            file_path: Path to YAML policy file

        Returns:
            Parsed Policy object

        Raises:
            PolicyValidationError: If policy is invalid
            FileNotFoundError: If file doesn't exist
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        return self.parse_string(content, source=str(path))

    def parse_string(self, content: str, source: str = '<string>') -> Policy:
        """Parse policy from YAML string.

        Args:
            content: YAML content string
            source: Source identifier for error messages

        Returns:
            Parsed Policy object

        Raises:
            PolicyValidationError: If policy is invalid
        """
        self._validation_errors = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise PolicyValidationError(f"Invalid YAML in {source}: {e}")

        if not isinstance(data, dict):
            raise PolicyValidationError(f"Policy must be a YAML mapping in {source}")

        self._validate_policy(data)

        if self._validation_errors:
            raise PolicyValidationError(
                f"Policy validation failed in {source}",
                errors=self._validation_errors
            )

        return self._build_policy(data)

    def parse_dict(self, data: dict) -> Policy:
        """Parse policy from dictionary.

        Args:
            data: Policy dictionary

        Returns:
            Parsed Policy object
        """
        self._validation_errors = []
        self._validate_policy(data)

        if self._validation_errors:
            raise PolicyValidationError(
                "Policy validation failed",
                errors=self._validation_errors
            )

        return self._build_policy(data)

    def load_default_policy(self) -> Policy:
        """Load default policy from policy directory.

        Returns:
            Default Policy object
        """
        default_path = Path(self._policy_dir) / 'protection_policy.yaml'

        if default_path.exists():
            return self.parse_file(default_path)

        return self._create_default_policy()

    def _validate_policy(self, data: dict) -> None:
        """Validate policy structure and values."""
        if 'version' not in data:
            self._validation_errors.append("Missing required field: version")

        if 'rules' not in data:
            self._validation_errors.append("Missing required field: rules")
        elif not isinstance(data['rules'], list):
            self._validation_errors.append("Field 'rules' must be a list")
        else:
            self._validate_rules(data['rules'])

        if 'settings' in data:
            self._validate_settings(data['settings'])

    def _validate_rules(self, rules: list) -> None:
        """Validate protection rules."""
        entity_types_seen = set()

        for i, rule in enumerate(rules):
            prefix = f"Rule {i + 1}"

            if not isinstance(rule, dict):
                self._validation_errors.append(f"{prefix}: Must be a mapping")
                continue

            if 'entity_type' not in rule:
                self._validation_errors.append(f"{prefix}: Missing entity_type")
            else:
                entity_type = rule['entity_type']
                if entity_type in entity_types_seen:
                    logger.warning(f"Duplicate rule for entity type: {entity_type}")
                entity_types_seen.add(entity_type)

            if 'protection_method' not in rule:
                self._validation_errors.append(f"{prefix}: Missing protection_method")
            elif rule['protection_method'] not in self.VALID_PROTECTION_METHODS:
                self._validation_errors.append(
                    f"{prefix}: Invalid protection_method '{rule['protection_method']}'. "
                    f"Valid: {self.VALID_PROTECTION_METHODS}"
                )

            if 'priority' in rule:
                if not isinstance(rule['priority'], int) or rule['priority'] < 1:
                    self._validation_errors.append(
                        f"{prefix}: priority must be positive integer"
                    )

            if 'options' in rule:
                self._validate_options(rule['options'], prefix)

    def _validate_options(self, options: dict, prefix: str) -> None:
        """Validate protection options."""
        if 'visible_chars' in options:
            if not isinstance(options['visible_chars'], int) or options['visible_chars'] < 0:
                self._validation_errors.append(
                    f"{prefix}: visible_chars must be non-negative integer"
                )

        if 'mask_char' in options:
            if not isinstance(options['mask_char'], str) or len(options['mask_char']) != 1:
                self._validation_errors.append(
                    f"{prefix}: mask_char must be single character"
                )

        if 'direction' in options:
            if options['direction'] not in self.VALID_DIRECTIONS:
                self._validation_errors.append(
                    f"{prefix}: direction must be one of {self.VALID_DIRECTIONS}"
                )

    def _validate_settings(self, settings: dict) -> None:
        """Validate policy settings."""
        if 'confidence_threshold' in settings:
            threshold = settings['confidence_threshold']
            if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
                self._validation_errors.append(
                    "confidence_threshold must be between 0 and 1"
                )

        if 'default_protection' in settings:
            if settings['default_protection'] not in self.VALID_PROTECTION_METHODS:
                self._validation_errors.append(
                    f"Invalid default_protection. Valid: {self.VALID_PROTECTION_METHODS}"
                )

    def _build_policy(self, data: dict) -> Policy:
        """Build Policy object from validated data."""
        rules = [ProtectionRule.from_dict(r) for r in data.get('rules', [])]
        rules.sort(key=lambda r: r.priority)

        return Policy(
            version=str(data.get('version', '1.0')),
            description=data.get('description', ''),
            settings=PolicySettings.from_dict(data.get('settings')),
            rules=rules,
            metadata=data.get('metadata', {})
        )

    def _create_default_policy(self) -> Policy:
        """Create default policy when no file exists."""
        return Policy(
            version='1.0',
            description='Default protection policy',
            settings=PolicySettings(),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1
                ),
                ProtectionRule(
                    entity_type='CREDIT_CARD',
                    protection_method='aes256_encrypt',
                    priority=1
                ),
                ProtectionRule(
                    entity_type='PHONE_NUMBER',
                    protection_method='masking',
                    priority=2
                ),
            ]
        )

    def _get_default_policy_dir(self) -> str:
        """Get default policy directory path."""
        current = Path(__file__).parent.parent.parent
        return str(current / 'policies')


def load_policy(path: Optional[Union[str, Path]] = None) -> Policy:
    """Convenience function to load policy.

    Args:
        path: Optional path to policy file

    Returns:
        Parsed Policy object
    """
    parser = PolicyParser()

    if path:
        return parser.parse_file(path)

    return parser.load_default_policy()
