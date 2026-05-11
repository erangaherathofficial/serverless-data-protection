"""YAML policy configuration parser."""

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union


class PolicyValidationError(Exception):
    """Raised when policy validation fails."""

    def __init__(
            self, message: str, errors: Optional[list[str]] = None
    ) -> None:
        super().__init__(message)
        self.errors = errors or []


@dataclass
class ProtectionOptions:
    """Options for a protection method."""

    mask_char: str = '*'
    visible_chars: int = 4
    direction: str = 'right'
    token_prefix: str = 'TOK_'

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> 'ProtectionOptions':
        """Create from dictionary."""
        if not data:
            return cls()
        return cls(
            mask_char=data.get('mask_char', '*'),
            visible_chars=data.get('visible_chars', 4),
            direction=data.get('direction', 'right'),
            token_prefix=data.get('token_prefix', 'TOK_'),
        )


@dataclass
class ProtectionRule:
    """A single protection rule from policy."""

    entity_type: str
    protection_method: str
    priority: int = 1
    description: str = ''
    options: ProtectionOptions = field(default_factory=ProtectionOptions)

    @classmethod
    def from_dict(cls, data: dict) -> 'ProtectionRule':
        """Create rule from dictionary."""
        return cls(
            entity_type=data['entity_type'],
            protection_method=data['protection_method'],
            priority=data.get('priority', 1),
            description=data.get('description', ''),
            options=ProtectionOptions.from_dict(data.get('options')),
        )


@dataclass
class PolicySettings:
    """Global policy settings."""

    default_protection: str = 'masking'
    confidence_threshold: float = 0.7

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> 'PolicySettings':
        """Create from dictionary."""
        if not data:
            return cls()
        return cls(
            default_protection=data.get('default_protection', 'masking'),
            confidence_threshold=data.get('confidence_threshold', 0.7),
        )


@dataclass
class Policy:
    """Parsed protection policy."""

    version: str
    description: str
    settings: PolicySettings
    rules: list[ProtectionRule]

    def get_rule_for_entity(
            self, entity_type: str
    ) -> Optional[ProtectionRule]:
        """Get highest priority rule for entity type."""
        matching = [r for r in self.rules if r.entity_type == entity_type]
        if not matching:
            return None
        return min(matching, key=lambda r: r.priority)


class PolicyParser:
    """Parser for YAML protection policies."""

    VALID_PROTECTION_METHODS = [
        'aes256_encrypt',
        'sha256_hash',
        'masking',
        'tokenization',
        'redact',
    ]

    VALID_DIRECTIONS = ['left', 'right', 'center']

    def __init__(self, policy_dir: Optional[str] = None) -> None:
        """Initialize parser.

        Args:
            policy_dir: Directory containing policy files
        """
        if policy_dir is None:
            policy_dir = str(Path(__file__).parent.parent.parent / 'policies')
        self._policy_dir = policy_dir
        self._validation_errors: list[str] = []

    def parse_file(self, file_path: Union[str, Path]) -> Policy:
        """Parse policy from YAML file.

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

        Raises:
            PolicyValidationError: If policy is invalid
        """
        self._validation_errors = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise PolicyValidationError(
                f"Invalid YAML in {source}: {e}"
            ) from e

        if not isinstance(data, dict):
            raise PolicyValidationError(
                f"Policy must be a YAML mapping in {source}"
            )

        self._validate_policy(data)

        if self._validation_errors:
            raise PolicyValidationError(
                f"Policy validation failed in {source}",
                errors=self._validation_errors,
            )

        return self._build_policy(data)

    def load_default_policy(self) -> Policy:
        """Load the bundled default policy from the policy directory."""
        return self.parse_file(
            Path(self._policy_dir) / 'protection_policy.yaml'
        )

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
                msg = f"{prefix}: Missing entity_type"
                self._validation_errors.append(msg)
            else:
                entity_type = rule['entity_type']
                if entity_type in entity_types_seen:
                    msg = f"Duplicate rule for entity type: {entity_type}"
                    self._validation_errors.append(msg)
                entity_types_seen.add(entity_type)

            if 'protection_method' not in rule:
                msg = f"{prefix}: Missing protection_method"
                self._validation_errors.append(msg)
            else:
                method = rule['protection_method']
                if method not in self.VALID_PROTECTION_METHODS:
                    msg = (
                        f"{prefix}: Invalid protection_method '{method}'. "
                        f"Valid: {self.VALID_PROTECTION_METHODS}"
                    )
                    self._validation_errors.append(msg)

            if 'priority' in rule:
                is_valid = (
                        isinstance(rule['priority'], int) and rule['priority'] >= 1
                )
                if not is_valid:
                    msg = f"{prefix}: priority must be positive integer"
                    self._validation_errors.append(msg)

            if 'options' in rule:
                self._validate_options(rule['options'], prefix)

    def _validate_options(self, options: dict, prefix: str) -> None:
        """Validate protection options."""
        if 'visible_chars' in options:
            val = options['visible_chars']
            if not isinstance(val, int) or val < 0:
                msg = f"{prefix}: visible_chars must be non-negative integer"
                self._validation_errors.append(msg)

        if 'mask_char' in options:
            val = options['mask_char']
            if not isinstance(val, str) or len(val) != 1:
                msg = f"{prefix}: mask_char must be single character"
                self._validation_errors.append(msg)

        if 'direction' in options:
            if options['direction'] not in self.VALID_DIRECTIONS:
                msg = (
                    f"{prefix}: direction must be one of "
                    f"{self.VALID_DIRECTIONS}"
                )
                self._validation_errors.append(msg)

    def _validate_settings(self, settings: dict) -> None:
        """Validate policy settings."""
        if 'confidence_threshold' in settings:
            threshold = settings['confidence_threshold']
            valid_type = isinstance(threshold, (int, float))
            in_range = 0 <= threshold <= 1 if valid_type else False
            if not valid_type or not in_range:
                msg = "confidence_threshold must be between 0 and 1"
                self._validation_errors.append(msg)

        if 'default_protection' in settings:
            default_prot = settings['default_protection']
            if default_prot not in self.VALID_PROTECTION_METHODS:
                msg = (
                    "Invalid default_protection. "
                    f"Valid: {self.VALID_PROTECTION_METHODS}"
                )
                self._validation_errors.append(msg)

    def _build_policy(self, data: dict) -> Policy:
        """Build Policy object from validated data."""
        rules = [ProtectionRule.from_dict(r) for r in data.get('rules', [])]
        rules.sort(key=lambda r: r.priority)

        return Policy(
            version=str(data.get('version', '1.0')),
            description=data.get('description', ''),
            settings=PolicySettings.from_dict(data.get('settings')),
            rules=rules,
        )


def load_policy(path: Optional[Union[str, Path]] = None) -> Policy:
    """Load a policy from ``path`` if given, otherwise the bundled default."""
    parser = PolicyParser()
    if path:
        return parser.parse_file(path)
    return parser.load_default_policy()
