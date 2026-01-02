"""Pipeline orchestrator for data protection workflow."""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

import pandas as pd

from src.detection.presidio_detector import DetectionResult, PresidioDetector, create_detector
from src.handlers.base_handler import ProcessedData
from src.handlers.handler_factory import HandlerFactory, get_handler
from src.policy.policy_parser import Policy, load_policy
from src.policy.protection_mapper import ProtectionMapper
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
    original_schema: Optional[dict] = None
    detection_summary: Optional[dict] = None
    protection_summary: Optional[dict] = None
    total_duration_ms: float = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: Optional[str] = None

    def add_stage_result(self, result: StageResult) -> None:
        """Add stage result."""
        self.stage_results.append(result)
        if not result.success:
            self.success = False

    def get_stage(self, stage: PipelineStage) -> Optional[StageResult]:
        """Get result for specific stage."""
        for sr in self.stage_results:
            if sr.stage == stage:
                return sr
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'success': self.success,
            'file_name': self.file_name,
            'file_format': self.file_format,
            'total_duration_ms': self.total_duration_ms,
            'timestamp': self.timestamp,
            'error': self.error,
            'stages': [
                {
                    'stage': sr.stage.value,
                    'success': sr.success,
                    'duration_ms': sr.duration_ms,
                    'error': sr.error,
                    'metadata': sr.metadata
                }
                for sr in self.stage_results
            ],
            'detection_summary': self.detection_summary,
            'protection_summary': self.protection_summary
        }


class PipelineOrchestrator:
    """Orchestrates the 7-step data protection pipeline.

    Pipeline Steps:
    1. RECEIVE - Receive file content from S3
    2. VALIDATE - Validate file format (CSV, JSON, Parquet)
    3. DETECT - Scan for PII using Presidio
    4. EVALUATE - Evaluate policy and generate protection plan
    5. PROTECT - Apply protection techniques
    6. SCHEMA_CHECK - Validate schema preservation
    7. OUTPUT - Serialize protected data for storage
    """

    def __init__(
        self,
        policy: Optional[Policy] = None,
        detector: Optional[PresidioDetector] = None,
        fail_fast: bool = True
    ) -> None:
        """Initialize pipeline orchestrator.

        Args:
            policy: Protection policy (loads default if None)
            detector: PII detector (creates default if None)
            fail_fast: Stop on first error
        """
        self._policy = policy or load_policy()
        self._detector = detector or create_detector(
            score_threshold=self._policy.settings.confidence_threshold
        )
        self._fail_fast = fail_fast
        self._schema_validator = SchemaValidator()
        self._rule_evaluator = RuleEvaluator(self._policy)
        self._protection_mapper = ProtectionMapper(self._policy)

        self._stage_hooks: dict[PipelineStage, list[Callable]] = {
            stage: [] for stage in PipelineStage
        }

    def process(self, content: bytes, file_name: str) -> PipelineResult:
        """Execute the complete protection pipeline.

        Args:
            content: Raw file content
            file_name: Original file name

        Returns:
            PipelineResult with protected data and metadata
        """
        start_time = time.time()

        result = PipelineResult(
            success=True,
            file_name=file_name,
            file_format=self._get_format(file_name)
        )

        try:
            # Stage 1: Receive
            stage_result = self._stage_receive(content, file_name)
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            # Stage 2: Validate and Parse
            stage_result = self._stage_validate(content, file_name)
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            processed_data: ProcessedData = stage_result.data
            original_df = processed_data.dataframe.copy()
            result.original_schema = processed_data.metadata.schema

            # Stage 3: Detect PII
            stage_result = self._stage_detect(processed_data.dataframe)
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            detection_result: DetectionResult = stage_result.data
            result.detection_summary = detection_result.to_dict()

            # Stage 4: Evaluate Policy
            stage_result = self._stage_evaluate(detection_result)
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            evaluation_result: EvaluationResult = stage_result.data

            # Stage 5: Apply Protection
            stage_result = self._stage_protect(
                processed_data.dataframe,
                detection_result,
                evaluation_result
            )
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            protected_df: pd.DataFrame = stage_result.data
            result.protection_summary = stage_result.metadata

            # Stage 6: Schema Validation
            stage_result = self._stage_schema_check(original_df, protected_df)
            result.add_stage_result(stage_result)
            if not stage_result.success and self._fail_fast:
                return self._finalize_result(result, start_time)

            # Stage 7: Output
            handler = get_handler(file_name)
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
        """Stage 1: Receive and validate input."""
        start = time.time()
        self._run_hooks(PipelineStage.RECEIVE, 'before', content, file_name)

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

            result = StageResult(
                stage=PipelineStage.RECEIVE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                metadata={
                    'file_name': file_name,
                    'content_size': len(content)
                }
            )

            self._run_hooks(PipelineStage.RECEIVE, 'after', result)
            return result

        except Exception as e:
            return StageResult(
                stage=PipelineStage.RECEIVE,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_validate(self, content: bytes, file_name: str) -> StageResult:
        """Stage 2: Validate and parse file."""
        start = time.time()
        self._run_hooks(PipelineStage.VALIDATE, 'before', content, file_name)

        try:
            handler = get_handler(file_name)
            processed_data = handler.process(content, file_name)

            result = StageResult(
                stage=PipelineStage.VALIDATE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=processed_data,
                metadata={
                    'format': processed_data.metadata.file_format,
                    'rows': processed_data.metadata.row_count,
                    'columns': processed_data.metadata.column_count
                }
            )

            self._run_hooks(PipelineStage.VALIDATE, 'after', result)
            return result

        except Exception as e:
            return StageResult(
                stage=PipelineStage.VALIDATE,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_detect(self, df: pd.DataFrame) -> StageResult:
        """Stage 3: Detect PII entities."""
        start = time.time()
        self._run_hooks(PipelineStage.DETECT, 'before', df)

        try:
            detection_result = self._detector.detect_dataframe(df)

            result = StageResult(
                stage=PipelineStage.DETECT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=detection_result,
                metadata={
                    'entities_found': len(detection_result.entities),
                    'entity_types': detection_result.entity_counts,
                    'columns_with_pii': list(detection_result.columns_with_pii),
                    'cells_scanned': detection_result.total_cells_scanned
                }
            )

            self._run_hooks(PipelineStage.DETECT, 'after', result)
            return result

        except Exception as e:
            return StageResult(
                stage=PipelineStage.DETECT,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_evaluate(self, detection_result: DetectionResult) -> StageResult:
        """Stage 4: Evaluate policy and generate protection plan."""
        start = time.time()
        self._run_hooks(PipelineStage.EVALUATE, 'before', detection_result)

        try:
            evaluation_result = self._rule_evaluator.evaluate(detection_result)

            result = StageResult(
                stage=PipelineStage.EVALUATE,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=evaluation_result,
                metadata=evaluation_result.statistics
            )

            self._run_hooks(PipelineStage.EVALUATE, 'after', result)
            return result

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
        detection_result: DetectionResult,
        evaluation_result: EvaluationResult
    ) -> StageResult:
        """Stage 5: Apply protection techniques."""
        start = time.time()
        self._run_hooks(PipelineStage.PROTECT, 'before', df, evaluation_result)

        try:
            protected_df = df.copy()
            protection_counts: dict[str, int] = {}

            for action in evaluation_result.actions:
                col = action.entity.column_name
                row = action.entity.row_index

                if col is None or row is None:
                    continue

                if col not in protected_df.columns:
                    continue

                if row >= len(protected_df):
                    continue

                current_value = str(protected_df.at[row, col])
                method = action.protection_method

                try:
                    strategy = ProtectionRegistry.get(method, action.options)
                    entity_text = action.entity.text
                    protected_text = strategy.protect(entity_text)

                    new_value = current_value.replace(entity_text, protected_text)
                    protected_df.at[row, col] = new_value

                    protection_counts[method] = protection_counts.get(method, 0) + 1

                except Exception as e:
                    logger.warning(f"Protection failed for {col}[{row}]: {e}")

            result = StageResult(
                stage=PipelineStage.PROTECT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=protected_df,
                metadata={
                    'protections_applied': sum(protection_counts.values()),
                    'methods_used': protection_counts
                }
            )

            self._run_hooks(PipelineStage.PROTECT, 'after', result)
            return result

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
        """Stage 6: Validate schema preservation."""
        start = time.time()
        self._run_hooks(PipelineStage.SCHEMA_CHECK, 'before', original_df, protected_df)

        try:
            validation_result = self._schema_validator.validate(
                original_df, protected_df
            )

            result = StageResult(
                stage=PipelineStage.SCHEMA_CHECK,
                success=validation_result.is_valid,
                duration_ms=self._elapsed_ms(start),
                data=validation_result,
                metadata={
                    'errors': len(validation_result.errors),
                    'warnings': len(validation_result.warnings)
                },
                error='; '.join(e.message for e in validation_result.errors) if not validation_result.is_valid else None
            )

            self._run_hooks(PipelineStage.SCHEMA_CHECK, 'after', result)
            return result

        except Exception as e:
            return StageResult(
                stage=PipelineStage.SCHEMA_CHECK,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def _stage_output(self, df: pd.DataFrame, handler) -> StageResult:
        """Stage 7: Serialize protected data."""
        start = time.time()
        self._run_hooks(PipelineStage.OUTPUT, 'before', df)

        try:
            serialized = handler.serialize(df)

            result = StageResult(
                stage=PipelineStage.OUTPUT,
                success=True,
                duration_ms=self._elapsed_ms(start),
                data=serialized,
                metadata={
                    'output_size': len(serialized),
                    'content_type': handler.get_content_type()
                }
            )

            self._run_hooks(PipelineStage.OUTPUT, 'after', result)
            return result

        except Exception as e:
            return StageResult(
                stage=PipelineStage.OUTPUT,
                success=False,
                duration_ms=self._elapsed_ms(start),
                error=str(e)
            )

    def register_hook(
        self,
        stage: PipelineStage,
        hook: Callable
    ) -> None:
        """Register a hook for a pipeline stage.

        Args:
            stage: Pipeline stage to hook
            hook: Callback function
        """
        self._stage_hooks[stage].append(hook)

    def _run_hooks(self, stage: PipelineStage, timing: str, *args) -> None:
        """Run hooks for a stage."""
        for hook in self._stage_hooks[stage]:
            try:
                hook(stage, timing, *args)
            except Exception as e:
                logger.warning(f"Hook error at {stage.value}/{timing}: {e}")

    def _get_format(self, file_name: str) -> str:
        """Extract format from file name."""
        if '.' in file_name:
            return file_name.rsplit('.', 1)[-1].upper()
        return 'UNKNOWN'

    def _elapsed_ms(self, start: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.time() - start) * 1000

    def _finalize_result(
        self,
        result: PipelineResult,
        start_time: float
    ) -> PipelineResult:
        """Finalize pipeline result."""
        result.total_duration_ms = (time.time() - start_time) * 1000
        return result


def create_pipeline(
    policy_path: Optional[str] = None,
    score_threshold: float = 0.7
) -> PipelineOrchestrator:
    """Create configured pipeline orchestrator.

    Args:
        policy_path: Path to policy file
        score_threshold: PII detection threshold

    Returns:
        Configured PipelineOrchestrator
    """
    policy = load_policy(policy_path) if policy_path else load_policy()
    detector = create_detector(score_threshold=score_threshold)

    return PipelineOrchestrator(policy=policy, detector=detector)
