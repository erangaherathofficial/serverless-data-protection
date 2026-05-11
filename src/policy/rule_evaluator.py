"""Rule evaluator for matching detected PII against policy rules."""

from dataclasses import dataclass, field
from typing import Optional

from src.detection.presidio_detector import DetectionResult, PIIEntity
from src.policy.policy_parser import Policy, ProtectionOptions, ProtectionRule


@dataclass
class ProtectionAction:
    """A protection action to apply to a detected entity."""

    entity: PIIEntity
    protection_method: str
    options: ProtectionOptions
    priority: int


@dataclass
class EvaluationResult:
    """Result of evaluating detection results against policy."""

    actions: list[ProtectionAction] = field(default_factory=list)
    actions_by_column: dict[str, list[ProtectionAction]] = field(
        default_factory=dict
    )
    statistics: dict = field(default_factory=dict)

    def add_action(self, action: ProtectionAction) -> None:
        self.actions.append(action)
        col = action.entity.column_name
        if col:
            self.actions_by_column.setdefault(col, []).append(action)


class RuleEvaluator:
    """Evaluates detected PII entities against protection policy rules.

    Every entity above the policy's confidence threshold produces an action:
    either a rule-driven one or a fallback using `settings.default_protection`.
    """

    _FALLBACK_PRIORITY = 999

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._rule_cache: dict[str, Optional[ProtectionRule]] = {}

    def evaluate(self, detection_result: DetectionResult) -> EvaluationResult:
        result = EvaluationResult()
        method_counts: dict[str, int] = {}
        entity_type_counts: dict[str, int] = {}

        for entity in detection_result.entities:
            if not self._meets_threshold(entity):
                continue

            action = self._action_for(entity)
            result.add_action(action)

            method_counts[action.protection_method] = (
                    method_counts.get(action.protection_method, 0) + 1
            )
            entity_type_counts[entity.entity_type] = (
                    entity_type_counts.get(entity.entity_type, 0) + 1
            )

        result.statistics = {
            'total_entities': len(detection_result.entities),
            'matched_entities': len(result.actions),
            'methods_used': method_counts,
            'entity_types': entity_type_counts,
        }

        return result

    def evaluate_entity(self, entity: PIIEntity) -> Optional[ProtectionAction]:
        if not self._meets_threshold(entity):
            return None
        return self._action_for(entity)

    def _action_for(self, entity: PIIEntity) -> ProtectionAction:
        rule = self._get_rule(entity.entity_type)
        if rule:
            return ProtectionAction(
                entity=entity,
                protection_method=rule.protection_method,
                options=rule.options,
                priority=rule.priority,
            )
        return ProtectionAction(
            entity=entity,
            protection_method=self._policy.settings.default_protection,
            options=ProtectionOptions(),
            priority=self._FALLBACK_PRIORITY,
        )

    def _get_rule(self, entity_type: str) -> Optional[ProtectionRule]:
        if entity_type not in self._rule_cache:
            self._rule_cache[entity_type] = self._policy.get_rule_for_entity(
                entity_type
            )
        return self._rule_cache[entity_type]

    def _meets_threshold(self, entity: PIIEntity) -> bool:
        return entity.score >= self._policy.settings.confidence_threshold
