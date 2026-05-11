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
)
from src.policy.rule_evaluator import (
    EvaluationResult,
    ProtectionAction,
    RuleEvaluator,
)

pytestmark = pytest.mark.unit


class TestProtectionOptions:
    """Tests for ProtectionOptions dataclass."""

    def test_default_values(self):
        options = ProtectionOptions()
        assert options.mask_char == '*'
        assert options.visible_chars == 4
        assert options.direction == 'right'

    def test_from_dict(self):
        options = ProtectionOptions.from_dict({
            'mask_char': 'X',
            'visible_chars': 2,
            'direction': 'left',
        })
        assert options.mask_char == 'X'
        assert options.visible_chars == 2
        assert options.direction == 'left'

    def test_from_dict_empty_or_none(self):
        assert ProtectionOptions.from_dict(None).mask_char == '*'
        assert ProtectionOptions.from_dict({}).visible_chars == 4


class TestProtectionRule:
    """Tests for ProtectionRule dataclass."""

    def test_from_dict_minimal(self):
        rule = ProtectionRule.from_dict({
            'entity_type': 'EMAIL_ADDRESS',
            'protection_method': 'sha256_hash',
        })
        assert rule.entity_type == 'EMAIL_ADDRESS'
        assert rule.protection_method == 'sha256_hash'
        assert rule.priority == 1

    def test_from_dict_full(self):
        rule = ProtectionRule.from_dict({
            'entity_type': 'PHONE_NUMBER',
            'protection_method': 'masking',
            'priority': 2,
            'description': 'Mask phone numbers',
            'options': {'mask_char': '#', 'visible_chars': 4},
        })
        assert rule.priority == 2
        assert rule.description == 'Mask phone numbers'
        assert rule.options.mask_char == '#'


class TestPolicyParser:
    """Tests for PolicyParser."""

    @pytest.fixture
    def parser(self):
        return PolicyParser()

    @pytest.fixture
    def valid_yaml(self):
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
        policy = parser.parse_string(valid_yaml)
        assert policy.version == '1.0'
        assert len(policy.rules) == 2
        assert policy.settings.confidence_threshold == 0.7

    def test_parse_invalid_yaml(self, parser):
        with pytest.raises(PolicyValidationError, match="Invalid YAML"):
            parser.parse_string("invalid: yaml: content:")

    def test_parse_missing_version(self, parser):
        yaml_content = """
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
"""
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string(yaml_content)
        assert 'version' in str(exc.value.errors)

    def test_parse_missing_rules(self, parser):
        with pytest.raises(PolicyValidationError) as exc:
            parser.parse_string('version: "1.0"\n')
        assert 'rules' in str(exc.value.errors)

    def test_parse_invalid_protection_method(self, parser):
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


class TestPolicy:
    """Tests for Policy dataclass."""

    @pytest.fixture
    def policy(self):
        return Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1,
                ),
                ProtectionRule(
                    entity_type='PHONE_NUMBER',
                    protection_method='masking',
                    priority=2,
                ),
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='aes256_encrypt',
                    priority=2,
                ),
            ],
        )

    def test_get_rule_for_entity_returns_highest_priority(self, policy):
        rule = policy.get_rule_for_entity('EMAIL_ADDRESS')
        assert rule is not None
        assert rule.protection_method == 'sha256_hash'
        assert rule.priority == 1

    def test_get_rule_for_unknown_entity(self, policy):
        assert policy.get_rule_for_entity('UNKNOWN_TYPE') is None


class TestRuleEvaluator:
    """Tests for RuleEvaluator."""

    @pytest.fixture
    def policy(self):
        return Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(confidence_threshold=0.5),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1,
                ),
                ProtectionRule(
                    entity_type='CREDIT_CARD',
                    protection_method='aes256_encrypt',
                    priority=1,
                ),
            ],
        )

    @pytest.fixture
    def evaluator(self, policy):
        return RuleEvaluator(policy)

    @pytest.fixture
    def detection_result(self):
        result = DetectionResult()
        result.add_entity(PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@example.com',
            start=0, end=16, score=0.95,
            column_name='email', row_index=0,
        ))
        result.add_entity(PIIEntity(
            entity_type='CREDIT_CARD',
            text='4111111111111111',
            start=0, end=16, score=0.9,
            column_name='card', row_index=0,
        ))
        return result

    def test_evaluate_detection_result(self, evaluator, detection_result):
        result = evaluator.evaluate(detection_result)
        assert len(result.actions) == 2
        assert 'email' in result.actions_by_column
        assert 'card' in result.actions_by_column

    def test_evaluate_entity_matching_rule(self, evaluator):
        action = evaluator.evaluate_entity(PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0, end=13, score=0.9,
        ))
        assert action is not None
        assert action.protection_method == 'sha256_hash'

    def test_evaluate_below_threshold_returns_none(self, evaluator):
        action = evaluator.evaluate_entity(PIIEntity(
            entity_type='EMAIL_ADDRESS',
            text='test@test.com',
            start=0, end=13, score=0.3,
        ))
        assert action is None

    def test_evaluate_unknown_entity_uses_default(self, evaluator):
        action = evaluator.evaluate_entity(PIIEntity(
            entity_type='UNKNOWN_TYPE',
            text='some data',
            start=0, end=9, score=0.9,
        ))
        assert action is not None
        assert action.protection_method == 'masking'


class TestEvaluationResult:
    """Tests for EvaluationResult."""

    def test_empty_result(self):
        result = EvaluationResult()
        assert len(result.actions) == 0
        assert result.actions_by_column == {}

    def test_add_action_indexes_by_column(self):
        result = EvaluationResult()
        action = ProtectionAction(
            entity=PIIEntity(
                entity_type='EMAIL_ADDRESS',
                text='test@test.com',
                start=0, end=13, score=0.9,
                column_name='email', row_index=0,
            ),
            protection_method='sha256_hash',
            options=ProtectionOptions(),
            priority=1,
        )
        result.add_action(action)
        assert len(result.actions) == 1
        assert result.actions_by_column['email'] == [action]
