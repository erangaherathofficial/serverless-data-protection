"""Unit tests for policy engine."""

import pytest

from src.detection.presidio_detector import DetectionResult, PIIEntity
from src.policy.policy_parser import (
    Policy,
    PolicyParser,
    PolicySettings,
    PolicyValidationError,
    ProtectionOptions,
    ProtectionRule,
    load_policy,
)
from src.policy.protection_mapper import (
    ColumnProtectionPlan,
    ProtectionMapper,
    ProtectionPlan,
    create_mapper,
)
from src.policy.rule_evaluator import (
    EvaluationResult,
    ProtectionAction,
    RuleEvaluator,
    create_evaluator,
)


class TestProtectionOptions:
    """Tests for ProtectionOptions dataclass."""

    def test_default_values(self):
        """Test default option values."""
        options = ProtectionOptions()
        assert options.mask_char == '*'
        assert options.visible_chars == 4
        assert options.direction == 'right'

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            'mask_char': 'X',
            'visible_chars': 2,
            'direction': 'left'
        }
        options = ProtectionOptions.from_dict(data)
        assert options.mask_char == 'X'
        assert options.visible_chars == 2
        assert options.direction == 'left'

    def test_from_dict_empty(self):
        """Test creation from None/empty dict."""
        options = ProtectionOptions.from_dict(None)
        assert options.mask_char == '*'

        options = ProtectionOptions.from_dict({})
        assert options.visible_chars == 4


class TestProtectionRule:
    """Tests for ProtectionRule dataclass."""

    def test_from_dict_minimal(self):
        """Test rule creation with minimal data."""
        data = {
            'entity_type': 'EMAIL_ADDRESS',
            'protection_method': 'sha256_hash'
        }
        rule = ProtectionRule.from_dict(data)
        assert rule.entity_type == 'EMAIL_ADDRESS'
        assert rule.protection_method == 'sha256_hash'
        assert rule.priority == 1

    def test_from_dict_full(self):
        """Test rule creation with all fields."""
        data = {
            'entity_type': 'PHONE_NUMBER',
            'protection_method': 'masking',
            'priority': 2,
            'description': 'Mask phone numbers',
            'options': {'mask_char': '#', 'visible_chars': 4}
        }
        rule = ProtectionRule.from_dict(data)
        assert rule.priority == 2
        assert rule.description == 'Mask phone numbers'
        assert rule.options.mask_char == '#'


class TestPolicyParser:
    """Tests for PolicyParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return PolicyParser()

    @pytest.fixture
    def valid_yaml(self):
        """Valid YAML policy content."""
        return """
version: "1.0"
description: "Test policy"
settings:
  default_protection: masking
  confidence_threshold: 0.7
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
    priority: 1
  - entity_type: PHONE_NUMBER
    protection_method: masking
    priority: 2
    options:
      mask_char: "*"
      visible_chars: 4
"""

    def test_parse_valid_yaml(self, parser, valid_yaml):
        """Test parsing valid YAML."""
        policy = parser.parse_string(valid_yaml)
        assert policy.version == '1.0'
        assert len(policy.rules) == 2
        assert policy.settings.confidence_threshold == 0.7

    def test_parse_invalid_yaml(self, parser):
        """Test parsing invalid YAML raises error."""
        with pytest.raises(PolicyValidationError):
            parser.parse_string("invalid: yaml: content:")

    def test_parse_missing_version(self, parser):
        """Test missing version field."""
        yaml_content = """
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
"""
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string(yaml_content)
        assert 'version' in str(exc.value.errors)

    def test_parse_missing_rules(self, parser):
        """Test missing rules field."""
        yaml_content = """
version: "1.0"
"""
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string(yaml_content)
        assert 'rules' in str(exc.value.errors)

    def test_parse_invalid_protection_method(self, parser):
        """Test invalid protection method."""
        yaml_content = """
version: "1.0"
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: invalid_method
"""
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string(yaml_content)
        assert 'protection_method' in str(exc.value.errors)

    def test_parse_invalid_threshold(self, parser):
        """Test invalid confidence threshold."""
        yaml_content = """
version: "1.0"
settings:
  confidence_threshold: 1.5
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
"""
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string(yaml_content)
        assert 'threshold' in str(exc.value.errors).lower()

    def test_parse_dict(self, parser, sample_protection_policy):
        """Test parsing from dictionary."""
        policy = parser.parse_dict(sample_protection_policy)
        assert policy.version == '1.0'
        assert len(policy.rules) == 5

    def test_create_default_policy(self, parser):
        """Test default policy creation."""
        policy = parser._create_default_policy()
        assert policy.version == '1.0'
        assert len(policy.rules) >= 3


class TestPolicy:
    """Tests for Policy dataclass."""

    @pytest.fixture
    def policy(self):
        """Create test policy."""
        return Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1
                ),
                ProtectionRule(
                    entity_type='PHONE_NUMBER',
                    protection_method='masking',
                    priority=2
                ),
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='aes256_encrypt',
                    priority=2
                ),
            ]
        )

    def test_get_rule_for_entity(self, policy):
        """Test getting highest priority rule."""
        rule = policy.get_rule_for_entity('EMAIL_ADDRESS')
        assert rule is not None
        assert rule.protection_method == 'sha256_hash'
        assert rule.priority == 1

    def test_get_rule_for_unknown_entity(self, policy):
        """Test getting rule for unknown entity."""
        rule = policy.get_rule_for_entity('UNKNOWN_TYPE')
        assert rule is None

    def test_get_rules_by_method(self, policy):
        """Test getting rules by method."""
        rules = policy.get_rules_by_method('masking')
        assert len(rules) == 1
        assert rules[0].entity_type == 'PHONE_NUMBER'

    def test_get_entity_types(self, policy):
        """Test getting all entity types."""
        types = policy.get_entity_types()
        assert 'EMAIL_ADDRESS' in types
        assert 'PHONE_NUMBER' in types

    def test_to_dict(self, policy):
        """Test policy serialization."""
        data = policy.to_dict()
        assert data['version'] == '1.0'
        assert len(data['rules']) == 3


class TestRuleEvaluator:
    """Tests for RuleEvaluator."""

    @pytest.fixture
    def policy(self):
        """Create test policy."""
        return Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(confidence_threshold=0.5),
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
            ]
        )

    @pytest.fixture
    def evaluator(self, policy):
        """Create evaluator instance."""
        return RuleEvaluator(policy)

    @pytest.fixture
    def detection_result(self):
        """Create sample detection result."""
        result = DetectionResult()
        result.add_entity(PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@example.com',
            start=0,
            end=16,
            score=0.95,
            column_name='email',
            row_index=0
        ))
        result.add_entity(PIIEntity(
            entity_type='CREDIT_CARD',
            text='4111111111111111',
            start=0,
            end=16,
            score=0.9,
            column_name='card',
            row_index=0
        ))
        return result

    def test_evaluate_detection_result(self, evaluator, detection_result):
        """Test evaluating detection results."""
        result = evaluator.evaluate(detection_result)

        assert len(result.actions) == 2
        assert 'email' in result.actions_by_column
        assert 'card' in result.actions_by_column

    def test_evaluate_entity(self, evaluator):
        """Test evaluating single entity."""
        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0,
            end=13,
            score=0.9
        )
        action = evaluator.evaluate_entity(entity)

        assert action is not None
        assert action.protection_method == 'sha256_hash'

    def test_evaluate_below_threshold(self, evaluator):
        """Test entity below confidence threshold."""
        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0,
            end=13,
            score=0.3
        )
        action = evaluator.evaluate_entity(entity)
        assert action is None

    def test_evaluate_unknown_entity_uses_default(self, evaluator):
        """Test unknown entity uses default protection."""
        entity = PIIEntity(
            entity_type='UNKNOWN_TYPE',
            text='some data',
            start=0,
            end=9,
            score=0.9
        )
        action = evaluator.evaluate_entity(entity)

        assert action is not None
        assert action.protection_method == 'masking'

    def test_get_protection_method(self, evaluator):
        """Test getting protection method for entity type."""
        method = evaluator.get_protection_method('EMAIL_ADDRESS')
        assert method == 'sha256_hash'

        method = evaluator.get_protection_method('UNKNOWN')
        assert method == 'masking'

    def test_has_rule_for(self, evaluator):
        """Test checking for explicit rules."""
        assert evaluator.has_rule_for('EMAIL_ADDRESS') is True
        assert evaluator.has_rule_for('UNKNOWN_TYPE') is False


class TestProtectionMapper:
    """Tests for ProtectionMapper."""

    @pytest.fixture
    def policy(self):
        """Create test policy."""
        return Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1
                ),
            ]
        )

    @pytest.fixture
    def mapper(self, policy):
        """Create mapper instance."""
        return ProtectionMapper(policy)

    def test_map_entity_to_method(self, mapper):
        """Test mapping entity to protection method."""
        method = mapper.map_entity_to_method('EMAIL_ADDRESS')
        assert method == 'sha256_hash'

    def test_map_entity_to_options(self, mapper):
        """Test mapping entity to protection options."""
        options = mapper.map_entity_to_options('EMAIL_ADDRESS')
        assert isinstance(options, ProtectionOptions)

    def test_create_protection_plan(self, mapper):
        """Test creating protection plan."""
        import pandas as pd

        df = pd.DataFrame({
            'email': ['test@example.com'],
            'name': ['John']
        })

        detection = DetectionResult()
        detection.add_entity(PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@example.com',
            start=0,
            end=16,
            score=0.95,
            column_name='email',
            row_index=0
        ))

        plan = mapper.create_protection_plan(df, detection)

        assert isinstance(plan, ProtectionPlan)
        assert 'email' in plan.get_affected_columns()

    def test_validate_plan(self, mapper):
        """Test plan validation."""
        import pandas as pd

        df = pd.DataFrame({'email': ['test@test.com']})

        plan = ProtectionPlan()
        column_plan = ColumnProtectionPlan(column_name='nonexistent')
        plan.add_column_plan('nonexistent', column_plan)

        errors = mapper.validate_plan(plan, df)
        assert len(errors) > 0
        assert 'nonexistent' in errors[0]


class TestEvaluationResult:
    """Tests for EvaluationResult."""

    def test_empty_result(self):
        """Test empty evaluation result."""
        result = EvaluationResult()
        assert len(result.actions) == 0
        assert len(result.unmatched_entities) == 0

    def test_add_action(self):
        """Test adding actions."""
        result = EvaluationResult()

        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0,
            end=13,
            score=0.9,
            column_name='email'
        )

        action = ProtectionAction(
            entity=entity,
            rule=ProtectionRule(
                entity_type='EMAIL_ADDRESS',
                protection_method='sha256_hash'
            ),
            protection_method='sha256_hash',
            options=ProtectionOptions(),
            priority=1
        )

        result.add_action(action)

        assert len(result.actions) == 1
        assert 'email' in result.actions_by_column

    def test_get_actions_for_column(self):
        """Test getting actions by column."""
        result = EvaluationResult()

        entity = PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0,
            end=13,
            score=0.9,
            column_name='email',
            row_index=0
        )

        action = ProtectionAction(
            entity=entity,
            rule=ProtectionRule(
                entity_type='EMAIL_ADDRESS',
                protection_method='sha256_hash'
            ),
            protection_method='sha256_hash',
            options=ProtectionOptions(),
            priority=1
        )

        result.add_action(action)

        actions = result.get_actions_for_column('email')
        assert len(actions) == 1

        actions = result.get_actions_for_column('other')
        assert len(actions) == 0
