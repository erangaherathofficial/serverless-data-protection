"""Rule evaluator for matching detected PII against policy rules."""

import logging
from dataclasses import dataclass, field
from typing import Optional

from src.detection.presidio_detector import DetectionResult, PIIEntity
from src.policy.policy_parser import Policy, ProtectionOptions, ProtectionRule

logger = logging.getLogger(__name__)


@dataclass
class ProtectionAction:
    """Describes a protection action to apply."""

    entity: PIIEntity
    rule: ProtectionRule
    protection_method: str
    options: ProtectionOptions
    priority: int

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'entity_type': self.entity.entity_type,
            'text': self.entity.text,
            'column': self.entity.column_name,
            'row': self.entity.row_index,
            'protection_method': self.protection_method,
            'priority': self.priority
        }


@dataclass
class EvaluationResult:
    """Result of evaluating detection results against policy."""

    actions: list[ProtectionAction] = field(default_factory=list)
    unmatched_entities: list[PIIEntity] = field(default_factory=list)
    actions_by_column: dict[str, list[ProtectionAction]] = field(default_factory=dict)
    statistics: dict = field(default_factory=dict)

    def add_action(self, action: ProtectionAction) -> None:
        """Add protection action."""
        self.actions.append(action)

        if action.entity.column_name:
            col = action.entity.column_name
            if col not in self.actions_by_column:
                self.actions_by_column[col] = []
            self.actions_by_column[col].append(action)

    def add_unmatched(self, entity: PIIEntity) -> None:
        """Add unmatched entity."""
        self.unmatched_entities.append(entity)

    def get_actions_for_column(self, column: str) -> list[ProtectionAction]:
        """Get all actions for a specific column."""
        return self.actions_by_column.get(column, [])

    def get_actions_for_row(self, row_index: int) -> list[ProtectionAction]:
        """Get all actions for a specific row."""
        return [a for a in self.actions if a.entity.row_index == row_index]

    def get_actions_by_method(self, method: str) -> list[ProtectionAction]:
        """Get actions using specific protection method."""
        return [a for a in self.actions if a.protection_method == method]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'total_actions': len(self.actions),
            'unmatched_count': len(self.unmatched_entities),
            'columns_affected': list(self.actions_by_column.keys()),
            'actions': [a.to_dict() for a in self.actions],
            'statistics': self.statistics
        }


class RuleEvaluator:
    """Evaluates detected PII entities against protection policy rules."""

    def __init__(self, policy: Policy) -> None:
        """Initialize evaluator with policy.

        Args:
            policy: Protection policy to evaluate against
        """
        self._policy = policy
        self._rule_cache: dict[str, Optional[ProtectionRule]] = {}

    @property
    def policy(self) -> Policy:
        """Get current policy."""
        return self._policy

    def evaluate(self, detection_result: DetectionResult) -> EvaluationResult:
        """Evaluate detection results against policy.

        Args:
            detection_result: PII detection results

        Returns:
            EvaluationResult with protection actions
        """
        result = EvaluationResult()
        method_counts: dict[str, int] = {}
        entity_type_counts: dict[str, int] = {}

        for entity in detection_result.entities:
            if not self._meets_threshold(entity):
                logger.debug(
                    f"Entity {entity.entity_type} below threshold: {entity.score}"
                )
                continue

            rule = self._get_rule(entity.entity_type)

            if rule:
                action = ProtectionAction(
                    entity=entity,
                    rule=rule,
                    protection_method=rule.protection_method,
                    options=rule.options,
                    priority=rule.priority
                )
                result.add_action(action)

                method_counts[rule.protection_method] = (
                    method_counts.get(rule.protection_method, 0) + 1
                )
                entity_type_counts[entity.entity_type] = (
                    entity_type_counts.get(entity.entity_type, 0) + 1
                )
            else:
                if self._policy.settings.default_protection != 'none':
                    action = self._create_default_action(entity)
                    result.add_action(action)
                    method_counts[action.protection_method] = (
                        method_counts.get(action.protection_method, 0) + 1
                    )
                else:
                    result.add_unmatched(entity)

        result.statistics = {
            'total_entities': len(detection_result.entities),
            'matched_entities': len(result.actions),
            'unmatched_entities': len(result.unmatched_entities),
            'methods_used': method_counts,
            'entity_types': entity_type_counts
        }

        return result

    def evaluate_entity(self, entity: PIIEntity) -> Optional[ProtectionAction]:
        """Evaluate a single entity against policy.

        Args:
            entity: PII entity to evaluate

        Returns:
            ProtectionAction if rule matches, None otherwise
        """
        if not self._meets_threshold(entity):
            return None

        rule = self._get_rule(entity.entity_type)

        if rule:
            return ProtectionAction(
                entity=entity,
                rule=rule,
                protection_method=rule.protection_method,
                options=rule.options,
                priority=rule.priority
            )

        if self._policy.settings.default_protection != 'none':
            return self._create_default_action(entity)

        return None

    def get_protection_method(self, entity_type: str) -> str:
        """Get protection method for entity type.

        Args:
            entity_type: Type of PII entity

        Returns:
            Protection method name
        """
        rule = self._get_rule(entity_type)
        if rule:
            return rule.protection_method
        return self._policy.settings.default_protection

    def get_protection_options(self, entity_type: str) -> ProtectionOptions:
        """Get protection options for entity type.

        Args:
            entity_type: Type of PII entity

        Returns:
            ProtectionOptions for the entity type
        """
        rule = self._get_rule(entity_type)
        if rule:
            return rule.options
        return ProtectionOptions()

    def has_rule_for(self, entity_type: str) -> bool:
        """Check if policy has rule for entity type.

        Args:
            entity_type: Type of PII entity

        Returns:
            True if explicit rule exists
        """
        return self._get_rule(entity_type) is not None

    def _get_rule(self, entity_type: str) -> Optional[ProtectionRule]:
        """Get cached rule for entity type."""
        if entity_type not in self._rule_cache:
            self._rule_cache[entity_type] = self._policy.get_rule_for_entity(
                entity_type
            )
        return self._rule_cache[entity_type]

    def _meets_threshold(self, entity: PIIEntity) -> bool:
        """Check if entity meets confidence threshold."""
        return entity.score >= self._policy.settings.confidence_threshold

    def _create_default_action(self, entity: PIIEntity) -> ProtectionAction:
        """Create action using default protection method."""
        default_rule = ProtectionRule(
            entity_type=entity.entity_type,
            protection_method=self._policy.settings.default_protection,
            priority=999,
            description='Default protection'
        )

        return ProtectionAction(
            entity=entity,
            rule=default_rule,
            protection_method=self._policy.settings.default_protection,
            options=ProtectionOptions(),
            priority=999
        )

    def clear_cache(self) -> None:
        """Clear rule lookup cache."""
        self._rule_cache.clear()


class ConditionalEvaluator:
    """Evaluates conditional rules based on context."""

    def __init__(self, rule: ProtectionRule) -> None:
        """Initialize with rule.

        Args:
            rule: Rule with conditions to evaluate
        """
        self._rule = rule

    def matches(self, context: dict) -> bool:
        """Check if rule conditions match context.

        Args:
            context: Context dictionary with metadata

        Returns:
            True if all conditions match
        """
        conditions = self._rule.conditions

        if not conditions:
            return True

        for key, expected in conditions.items():
            actual = context.get(key)

            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        return True


def create_evaluator(policy: Policy) -> RuleEvaluator:
    """Create rule evaluator from policy.

    Args:
        policy: Protection policy

    Returns:
        Configured RuleEvaluator
    """
    return RuleEvaluator(policy)
