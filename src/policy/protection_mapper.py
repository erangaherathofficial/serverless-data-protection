"""Protection mapper for mapping PII entities to protection strategies."""

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

import pandas as pd
from src.detection.presidio_detector import DetectionResult
from src.policy.policy_parser import Policy, ProtectionOptions
from src.policy.rule_evaluator import ProtectionAction, RuleEvaluator

logger = logging.getLogger(__name__)


class ProtectionStrategy(Protocol):
    """Protocol for protection strategy implementations."""

    def protect(self, value: str, options: ProtectionOptions) -> str:
        """Apply protection to value."""
        ...


@dataclass
class ProtectionPlan:
    """Plan for protecting a DataFrame."""

    column_plans: dict[str, 'ColumnProtectionPlan'] = field(
        default_factory=dict
    )
    total_entities: int = 0
    total_protections: int = 0

    def add_column_plan(
            self, column: str, plan: 'ColumnProtectionPlan'
    ) -> None:
        """Add protection plan for column."""
        self.column_plans[column] = plan
        self.total_protections += len(plan.cell_actions)

    def get_column_plan(self, column: str) -> Optional['ColumnProtectionPlan']:
        """Get plan for specific column."""
        return self.column_plans.get(column)

    def get_affected_columns(self) -> list[str]:
        """Get list of columns requiring protection."""
        return list(self.column_plans.keys())

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'columns': {
                col: plan.to_dict()
                for col, plan in self.column_plans.items()
            },
            'total_entities': self.total_entities,
            'total_protections': self.total_protections
        }


@dataclass
class CellAction:
    """Protection action for a single cell."""

    row_index: int
    original_text: str
    entity_type: str
    protection_method: str
    options: ProtectionOptions
    start: int
    end: int


@dataclass
class ColumnProtectionPlan:
    """Protection plan for a single column."""

    column_name: str
    cell_actions: list[CellAction] = field(default_factory=list)
    protection_methods: set[str] = field(default_factory=set)

    def add_action(self, action: CellAction) -> None:
        """Add cell action."""
        self.cell_actions.append(action)
        self.protection_methods.add(action.protection_method)

    def get_actions_for_row(self, row_index: int) -> list[CellAction]:
        """Get actions for specific row."""
        return [a for a in self.cell_actions if a.row_index == row_index]

    def has_actions_for_row(self, row_index: int) -> bool:
        """Check if row has protection actions."""
        return any(a.row_index == row_index for a in self.cell_actions)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'column_name': self.column_name,
            'action_count': len(self.cell_actions),
            'methods': list(self.protection_methods),
            'rows_affected': len(set(a.row_index for a in self.cell_actions))
        }


class ProtectionMapper:
    """Maps detected PII to protection strategies.

    Creates execution plans for applying protections.
    """

    def __init__(self, policy: Policy) -> None:
        """Initialize mapper with policy.

        Args:
            policy: Protection policy
        """
        self._policy = policy
        self._evaluator = RuleEvaluator(policy)
        self._strategy_registry: dict[str, ProtectionStrategy] = {}

    @property
    def policy(self) -> Policy:
        """Get current policy."""
        return self._policy

    def register_strategy(self, method_name: str,
                          strategy: ProtectionStrategy) -> None:
        """Register a protection strategy.

        Args:
            method_name: Name of protection method
            strategy: Strategy implementation
        """
        self._strategy_registry[method_name] = strategy

    def get_strategy(self, method_name: str) -> Optional[ProtectionStrategy]:
        """Get registered strategy by name."""
        return self._strategy_registry.get(method_name)

    def create_protection_plan(
            self,
            _df: pd.DataFrame,
            detection_result: DetectionResult
    ) -> ProtectionPlan:
        """Create protection plan from detection results.

        Args:
            _df: Source DataFrame (reserved for future validation)
            detection_result: PII detection results

        Returns:
            ProtectionPlan with cell-level actions
        """
        evaluation = self._evaluator.evaluate(detection_result)
        plan = ProtectionPlan(total_entities=len(detection_result.entities))

        column_actions: dict[str, list[ProtectionAction]] = {}
        for action in evaluation.actions:
            col = action.entity.column_name
            if col:
                if col not in column_actions:
                    column_actions[col] = []
                column_actions[col].append(action)

        for column, actions in column_actions.items():
            column_plan = ColumnProtectionPlan(column_name=column)

            for action in actions:
                cell_action = CellAction(
                    row_index=action.entity.row_index or 0,
                    original_text=action.entity.text,
                    entity_type=action.entity.entity_type,
                    protection_method=action.protection_method,
                    options=action.options,
                    start=action.entity.start,
                    end=action.entity.end
                )
                column_plan.add_action(cell_action)

            plan.add_column_plan(column, column_plan)

        return plan

    def map_entity_to_method(self, entity_type: str) -> str:
        """Map entity type to protection method.

        Args:
            entity_type: Type of PII entity

        Returns:
            Protection method name
        """
        return self._evaluator.get_protection_method(entity_type)

    def map_entity_to_options(self, entity_type: str) -> ProtectionOptions:
        """Map entity type to protection options.

        Args:
            entity_type: Type of PII entity

        Returns:
            ProtectionOptions for the entity
        """
        return self._evaluator.get_protection_options(entity_type)

    def get_column_protection_summary(
            self,
            detection_result: DetectionResult
    ) -> dict[str, dict[str, str]]:
        """Get summary of protection methods by column.

        Args:
            detection_result: PII detection results

        Returns:
            Mapping of column -> entity_type -> method
        """
        summary: dict[str, dict[str, str]] = {}

        for entity in detection_result.entities:
            if entity.column_name:
                col = entity.column_name
                if col not in summary:
                    summary[col] = {}

                if entity.entity_type not in summary[col]:
                    method = self.map_entity_to_method(entity.entity_type)
                    summary[col][entity.entity_type] = method

        return summary

    def validate_plan(self, plan: ProtectionPlan,
                      df: pd.DataFrame) -> list[str]:
        """Validate protection plan against DataFrame.

        Args:
            plan: Protection plan to validate
            df: Target DataFrame

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        for column in plan.get_affected_columns():
            if column not in df.columns:
                errors.append(f"Column '{column}' not found in DataFrame")
                continue

            column_plan = plan.get_column_plan(column)
            if column_plan:
                max_row = max(
                    (a.row_index for a in column_plan.cell_actions),
                    default=-1
                )
                if max_row >= len(df):
                    errors.append(
                        f"Column '{column}' has actions for row {max_row}, "
                        f"but DataFrame only has {len(df)} rows"
                    )

        for column, column_plan in plan.column_plans.items():
            for method in column_plan.protection_methods:
                if method not in self._strategy_registry and method != 'none':
                    if method not in ['aes256_encrypt', 'sha256_hash',
                                      'masking', 'tokenization', 'redact']:
                        errors.append(f"Unknown protection method: {method}")

        return errors


class ProtectionPlanExecutor:
    """Executes protection plans on DataFrames."""

    def __init__(self, mapper: ProtectionMapper) -> None:
        """Initialize executor.

        Args:
            mapper: Protection mapper with registered strategies
        """
        self._mapper = mapper
        self._apply_functions: dict[str, Callable] = {}

    def register_apply_function(
            self,
            method_name: str,
            func: Callable[[str, ProtectionOptions], str]
    ) -> None:
        """Register function to apply protection method.

        Args:
            method_name: Protection method name
            func: Function (value, options) -> protected value
        """
        self._apply_functions[method_name] = func

    def execute(self, df: pd.DataFrame,
                plan: ProtectionPlan) -> pd.DataFrame:
        """Execute protection plan on DataFrame.

        Args:
            df: Source DataFrame
            plan: Protection plan to execute

        Returns:
            New DataFrame with protections applied
        """
        result = df.copy()

        for column, column_plan in plan.column_plans.items():
            if column not in result.columns:
                continue

            rows_to_update: dict[int, list[CellAction]] = {}
            for action in column_plan.cell_actions:
                if action.row_index not in rows_to_update:
                    rows_to_update[action.row_index] = []
                rows_to_update[action.row_index].append(action)

            for row_idx, actions in rows_to_update.items():
                if row_idx >= len(result):
                    continue

                current_value = str(result.iloc[row_idx][column])
                protected_value = self._apply_protections(
                    current_value, actions
                )
                result.at[row_idx, column] = protected_value

        return result

    def _apply_protections(
            self,
            value: str,
            actions: list[CellAction]
    ) -> str:
        """Apply multiple protections to a value.

        Handles overlapping entities by processing from end to start.
        """
        sorted_actions = sorted(actions, key=lambda a: a.start, reverse=True)

        result = value
        for action in sorted_actions:
            if action.protection_method in self._apply_functions:
                func = self._apply_functions[action.protection_method]

                start = action.start
                end = action.end
                if 0 <= start < len(result) and start < end <= len(result):
                    original_segment = result[start:end]
                    protected_segment = func(original_segment, action.options)
                    result = result[:start] + protected_segment + result[end:]
                else:
                    result = func(result, action.options)

        return result


def create_mapper(policy: Policy) -> ProtectionMapper:
    """Create protection mapper from policy.

    Args:
        policy: Protection policy

    Returns:
        Configured ProtectionMapper
    """
    return ProtectionMapper(policy)
