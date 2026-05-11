"""Pipeline orchestrator for data protection workflow."""

import logging
import pandas as pd
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.detection.presidio_detector import (
    DetectionResult,
    PresidioDetector,
    create_detector,
)
from src.handlers.base_handler import BaseHandler, ProcessedData
from src.handlers.handler_factory import HandlerFactory, get_handler
from src.policy.policy_parser import Policy, load_policy
from src.policy.rule_evaluator import EvaluationResult, RuleEvaluator
from src.protection.base_protection import ProtectionRegistry
from src.validation.schema_validator import SchemaValidator

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Pipeline processing stages."""
    RECEIVE = 'receive'
    VALIDATE = 'validate'
    DETECT = 'detect'
    EVALUATE = 'evaluate'
    PROTECT = 'protect'
    SCHEMA_CHECK = 'schema_check'
    OUTPUT = 'output'


@dataclass
class StageResult:
    """Result of a single pipeline stage."""

    stage: PipelineStage
    success: bool
    duration_ms: float
    data: Any = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    """Complete pipeline execution result."""

    success: bool
    file_name: str
    file_format: str
    stage_results: list[StageResult] = field(default_factory=list)
    protected_data: Optional[bytes] = None
    detection_summary: Optional[dict] = None
    protection_summary: Optional[dict] = None
    total_duration_ms: float = 0
    error: Optional[str] = None

    def add_stage_result(self, result: StageResult) -> None:
        self.stage_results.append(result)
        if not result.success:
            self.success = False

    def get_stage(self, stage: PipelineStage) -> Optional[StageResult]:
        for sr in self.stage_results:
            if sr.stage == stage:
                return sr
        return None


class PipelineOrchestrator:
    """Orchestrates the 7-stage data protection pipeline.

    Stages: RECEIVE → VALIDATE → DETECT → EVALUATE → PROTECT → SCHEMA_CHECK → OUTPUT.
    On stage failure the pipeline returns the partial result; subsequent stages
    are skipped.
    """

    def __init__(
            self,
            policy: Optional[Policy] = None,
            detector: Optional[PresidioDetector] = None
    ) -> None:
        self._policy = policy or load_policy()
        self._detector = detector or create_detector(
            score_threshold=self._policy.settings.confidence_threshold
        )
        self._schema_validator = SchemaValidator()
        self._rule_evaluator = RuleEvaluator(self._policy)

    def process(self, content: bytes, file_name: str) -> PipelineResult:
        start_time = time.time()

        result = PipelineResult(
            success=True,
            file_name=file_name,
            file_format=HandlerFactory.format_name(file_name)
        )

        try:
            stage_result = self._stage_receive(content, file_name)
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            stage_result = self._stage_validate(content, file_name)
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            processed_data: ProcessedData = stage_result.data
            handler = stage_result.metadata.pop('handler')
            original_df = processed_data.dataframe.copy()

            stage_result = self._stage_detect(processed_data.dataframe)
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            detection_result: DetectionResult = stage_result.data
            result.detection_summary = detection_result.to_dict()

            stage_result = self._stage_evaluate(detection_result)
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            evaluation_result: EvaluationResult = stage_result.data

            stage_result = self._stage_protect(
                processed_data.dataframe,
                evaluation_result
            )
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            protected_df: pd.DataFrame = stage_result.data
            result.protection_summary = stage_result.metadata

            stage_result = self._stage_schema_check(original_df, protected_df)
            result.add_stage_result(stage_result)
            if not stage_result.success:
                return self._finalize_result(result, start_time)

            stage_result = self._stage_output(protected_df, handler)
            result.add_stage_result(stage_result)

            if stage_result.success:
                result.protected_data = stage_result.data

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            result.success = False
            result.error = str(e)

        return self._finalize_result(result, start_time)

    def _stage_receive(self, content: bytes, file_name: str) -> StageResult:
        start = time.time()
        try:
            if not content:
                return StageResult(
                    stage=PipelineStage.RECEIVE,
                    success=False,
                    duration_ms=self._elapsed_ms(start),
                    error="Empty content received"
                )

            if not HandlerFactory.is_supported(file_name):
                return StageResult(
                    stage=PipelineStage.RECEIVE,
                    success=False,
                    duration_ms=self._elapsed_ms(start),
                    error=f"Unsupported file format: {file_name}"
                )

            return StageResult(
                stage=PipelineStage.RECEIVE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                metadata={
                    'file_name': file_name,
                    'content_size': len(content)
                }
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.RECEIVE,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_validate(self, content: bytes, file_name: str) -> StageResult:
        start = time.time()
        try:
            handler = get_handler(file_name)
            processed_data = handler.process(content, file_name)

            return StageResult(
                stage=PipelineStage.VALIDATE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=processed_data,
                metadata={
                    'format': processed_data.metadata.file_format,
                    'rows': processed_data.metadata.row_count,
                    'columns': processed_data.metadata.column_count,
                    'handler': handler,
                }
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.VALIDATE,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_detect(self, df: pd.DataFrame) -> StageResult:
        start = time.time()
        try:
            detection_result = self._detector.detect_dataframe(df)

            return StageResult(
                stage=PipelineStage.DETECT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=detection_result,
                metadata={
                    'entities_found': len(detection_result.entities),
                    'entity_types': detection_result.entity_counts,
                    'columns_with_pii': list(
                        detection_result.columns_with_pii
                    ),
                    'cells_scanned': detection_result.total_cells_scanned
                }
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.DETECT,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_evaluate(
            self, detection_result: DetectionResult
    ) -> StageResult:
        start = time.time()
        try:
            evaluation_result = self._rule_evaluator.evaluate(detection_result)

            return StageResult(
                stage=PipelineStage.EVALUATE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=evaluation_result,
                metadata=evaluation_result.statistics
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.EVALUATE,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_protect(
            self,
            df: pd.DataFrame,
            evaluation_result: EvaluationResult
    ) -> StageResult:
        start = time.time()
        try:
            protected_df = df.copy()
            protection_counts: dict[str, int] = {}
            failures = 0

            ordered_actions = sorted(
                evaluation_result.actions, key=lambda a: a.priority
            )
            applied_spans: dict[tuple[int, str], list[tuple[int, int]]] = {}
            for action in ordered_actions:
                col = action.entity.column_name
                row = action.entity.row_index

                if col is None or row is None:
                    continue

                if col not in protected_df.columns:
                    continue

                if row >= len(protected_df):
                    continue

                e_start = action.entity.start
                e_end = action.entity.end
                spans = applied_spans.setdefault((row, col), [])
                if any(s <= e_start and e_end <= e for s, e in spans):
                    continue

                current_value = str(protected_df.at[row, col])
                method = action.protection_method

                try:
                    strategy = ProtectionRegistry.get(method, action.options)
                    entity_text = action.entity.text
                    protected_text = strategy.protect(entity_text)

                    new_value = current_value.replace(
                        entity_text, protected_text
                    )
                    protected_df.at[row, col] = new_value

                    spans.append((e_start, e_end))
                    protection_counts[method] = (
                            protection_counts.get(method, 0) + 1
                    )

                except Exception as e:
                    failures += 1
                    logger.debug(f"Protection failed for {col}[{row}]: {e}")

            if failures:
                logger.warning(
                    f"Protection skipped {failures} action(s); "
                    f"see debug logs for details"
                )

            return StageResult(
                stage=PipelineStage.PROTECT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=protected_df,
                metadata={
                    'protections_applied': sum(protection_counts.values()),
                    'methods_used': protection_counts,
                    'failures': failures,
                }
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.PROTECT,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_schema_check(
            self,
            original_df: pd.DataFrame,
            protected_df: pd.DataFrame
    ) -> StageResult:
        start = time.time()
        try:
            validation_result = self._schema_validator.validate(
                original_df, protected_df
            )

            return StageResult(
                stage=PipelineStage.SCHEMA_CHECK,
                success=validation_result.is_valid,
                duration_ms=self._elapsed_ms(start),
                data=validation_result,
                metadata={
                    'errors': len(validation_result.errors),
                    'warnings': len(validation_result.warnings)
                },
                error=(
                    '; '.join(e.message for e in validation_result.errors)
                    if not validation_result.is_valid else None
                )
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.SCHEMA_CHECK,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_output(
            self, df: pd.DataFrame, handler: BaseHandler
    ) -> StageResult:
        start = time.time()
        try:
            serialized = handler.serialize(df)

            return StageResult(
                stage=PipelineStage.OUTPUT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=serialized,
                metadata={
                    'output_size': len(serialized),
                    'content_type': handler.get_content_type()
                }
            )

        except Exception as e:
            return StageResult(
                stage=PipelineStage.OUTPUT,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _elapsed_ms(self, start: float) -> float:
        return (time.time() - start) * 1000

    def _finalize_result(
            self,
            result: PipelineResult,
            start_time: float
    ) -> PipelineResult:
        result.total_duration_ms = (time.time() - start_time) * 1000
        return result


def create_pipeline(policy_path: Optional[str] = None) -> PipelineOrchestrator:
    """Create a pipeline whose detection threshold is read from the policy."""
    return PipelineOrchestrator(policy=load_policy(policy_path))
