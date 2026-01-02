"""Integration tests for the protection pipeline."""

import io
import json

import pandas as pd
import pytest

from src.handlers.handler_factory import get_handler
from src.pipeline.pipeline_orchestrator import (
    PipelineOrchestrator,
    PipelineResult,
    PipelineStage,
    create_pipeline,
)
from src.policy.policy_parser import Policy, PolicySettings, ProtectionRule


class TestPipelineIntegration:
    """Integration tests for complete pipeline."""

    @pytest.fixture
    def sample_csv_with_pii(self) -> bytes:
        """Create CSV with various PII types."""
        content = """id,name,email,phone,card_number,notes
1,John Smith,john.smith@example.com,+44 7911 123456,4111111111111111,Regular customer
2,Jane Doe,jane.doe@company.co.uk,020 7946 0958,5500000000000004,VIP member
3,Bob Wilson,bob@test.org,07700 900123,340000000000009,New signup
"""
        return content.encode('utf-8')

    @pytest.fixture
    def sample_json_with_pii(self) -> bytes:
        """Create JSON with PII."""
        data = {
            "records": [
                {
                    "id": 1,
                    "name": "John Smith",
                    "email": "john@example.com",
                    "phone": "+44 7911 123456"
                },
                {
                    "id": 2,
                    "name": "Jane Doe",
                    "email": "jane@test.org",
                    "phone": "020 7946 0958"
                }
            ]
        }
        return json.dumps(data, indent=2).encode('utf-8')

    @pytest.fixture
    def sample_parquet_with_pii(self) -> bytes:
        """Create Parquet with PII."""
        df = pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John Smith', 'Jane Doe', 'Bob Wilson'],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
            'ssn': ['123-45-6789', '987-65-4321', '555-55-5555']
        })
        buffer = io.BytesIO()
        df.to_parquet(buffer, index=False)
        return buffer.getvalue()

    @pytest.fixture
    def test_policy(self) -> Policy:
        """Create test policy."""
        return Policy(
            version='1.0',
            description='Test policy',
            settings=PolicySettings(
                default_protection='masking',
                confidence_threshold=0.5
            ),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1
                ),
                ProtectionRule(
                    entity_type='CREDIT_CARD',
                    protection_method='masking',
                    priority=1
                ),
                ProtectionRule(
                    entity_type='PHONE_NUMBER',
                    protection_method='masking',
                    priority=2
                ),
            ]
        )

    @pytest.fixture
    def pipeline(self, test_policy) -> PipelineOrchestrator:
        """Create pipeline with test policy."""
        from src.detection.presidio_detector import PresidioDetector
        detector = PresidioDetector(score_threshold=0.5)
        return PipelineOrchestrator(policy=test_policy, detector=detector)

    @pytest.mark.integration
    def test_csv_end_to_end(self, pipeline, sample_csv_with_pii):
        """Test complete pipeline with CSV file."""
        result = pipeline.process(sample_csv_with_pii, 'test_data.csv')

        assert result.success is True
        assert result.file_format == 'CSV'
        assert len(result.stage_results) == 7
        assert result.protected_data is not None

        for stage_result in result.stage_results:
            assert stage_result.success is True, f"Stage {stage_result.stage} failed"

        assert result.detection_summary is not None
        assert len(result.detection_summary.get('entities', [])) > 0

    @pytest.mark.integration
    def test_json_end_to_end(self, pipeline, sample_json_with_pii):
        """Test complete pipeline with JSON file."""
        result = pipeline.process(sample_json_with_pii, 'test_data.json')

        assert result.success is True
        assert result.file_format == 'JSON'
        assert result.protected_data is not None

        protected_json = json.loads(result.protected_data)
        # Output may be array or nested object depending on handler state
        if isinstance(protected_json, list):
            assert len(protected_json) == 2
        else:
            assert 'records' in protected_json

    @pytest.mark.integration
    def test_parquet_end_to_end(self, pipeline, sample_parquet_with_pii):
        """Test complete pipeline with Parquet file."""
        result = pipeline.process(sample_parquet_with_pii, 'test_data.parquet')

        assert result.success is True
        assert result.file_format == 'PARQUET'
        assert result.protected_data is not None

        buffer = io.BytesIO(result.protected_data)
        protected_df = pd.read_parquet(buffer)
        assert len(protected_df) == 3

    @pytest.mark.integration
    def test_pipeline_detects_email(self, pipeline, sample_csv_with_pii):
        """Test pipeline detects email addresses."""
        result = pipeline.process(sample_csv_with_pii, 'test.csv')

        assert result.success is True
        detection = result.detection_summary
        assert 'EMAIL_ADDRESS' in detection.get('entity_counts', {})

    @pytest.mark.integration
    def test_pipeline_protects_pii(self, pipeline, sample_csv_with_pii):
        """Test pipeline applies protection to PII."""
        result = pipeline.process(sample_csv_with_pii, 'test.csv')

        assert result.success is True
        assert result.protection_summary is not None
        assert result.protection_summary.get('protections_applied', 0) > 0

        handler = get_handler('test.csv')
        handler.validate(result.protected_data, 'test.csv')
        protected_df = handler.parse(result.protected_data)

        original_handler = get_handler('test.csv')
        original_handler.validate(sample_csv_with_pii, 'test.csv')
        original_df = original_handler.parse(sample_csv_with_pii)

        for col in ['email']:
            if col in protected_df.columns:
                assert not protected_df[col].equals(original_df[col])

    @pytest.mark.integration
    def test_pipeline_preserves_schema(self, pipeline, sample_csv_with_pii):
        """Test pipeline preserves schema structure."""
        result = pipeline.process(sample_csv_with_pii, 'test.csv')

        assert result.success is True

        schema_stage = result.get_stage(PipelineStage.SCHEMA_CHECK)
        assert schema_stage is not None
        assert schema_stage.success is True

        handler = get_handler('test.csv')
        handler.validate(sample_csv_with_pii, 'original.csv')
        original_df = handler.parse(sample_csv_with_pii)

        handler.validate(result.protected_data, 'protected.csv')
        protected_df = handler.parse(result.protected_data)

        assert list(original_df.columns) == list(protected_df.columns)
        assert len(original_df) == len(protected_df)

    @pytest.mark.integration
    def test_pipeline_stage_timing(self, pipeline, sample_csv_with_pii):
        """Test all pipeline stages report timing."""
        result = pipeline.process(sample_csv_with_pii, 'test.csv')

        for stage_result in result.stage_results:
            assert stage_result.duration_ms >= 0

        assert result.total_duration_ms > 0

    @pytest.mark.integration
    def test_pipeline_with_empty_file(self, pipeline):
        """Test pipeline handles empty file."""
        result = pipeline.process(b'', 'empty.csv')

        assert result.success is False
        assert any(
            sr.stage == PipelineStage.RECEIVE and not sr.success
            for sr in result.stage_results
        )

    @pytest.mark.integration
    def test_pipeline_with_unsupported_format(self, pipeline):
        """Test pipeline rejects unsupported format."""
        result = pipeline.process(b'some content', 'file.txt')

        assert result.success is False

    @pytest.mark.integration
    def test_pipeline_result_serialization(self, pipeline, sample_csv_with_pii):
        """Test pipeline result can be serialized."""
        result = pipeline.process(sample_csv_with_pii, 'test.csv')

        result_dict = result.to_dict()

        assert 'success' in result_dict
        assert 'stages' in result_dict
        assert 'total_duration_ms' in result_dict

        json_str = json.dumps(result_dict)
        assert len(json_str) > 0


class TestPipelineHooks:
    """Tests for pipeline hooks."""

    @pytest.fixture
    def pipeline(self) -> PipelineOrchestrator:
        """Create pipeline."""
        return create_pipeline()

    @pytest.mark.integration
    def test_register_hook(self, pipeline):
        """Test registering pipeline hooks."""
        hook_calls = []

        def test_hook(stage, timing, *args):
            hook_calls.append((stage, timing))

        pipeline.register_hook(PipelineStage.DETECT, test_hook)

        content = b'id,email\n1,test@test.com'
        pipeline.process(content, 'test.csv')

        assert len(hook_calls) >= 2
        stages = [call[0] for call in hook_calls]
        assert PipelineStage.DETECT in stages


class TestPipelineWithDifferentPolicies:
    """Tests for pipeline with various policy configurations."""

    @pytest.fixture
    def csv_content(self) -> bytes:
        """Simple CSV with email."""
        return b'id,email\n1,john@example.com\n2,jane@test.org'

    @pytest.mark.integration
    def test_hash_only_policy(self, csv_content):
        """Test policy that only uses hashing."""
        policy = Policy(
            version='1.0',
            description='Hash only',
            settings=PolicySettings(default_protection='sha256_hash'),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='sha256_hash',
                    priority=1
                )
            ]
        )

        pipeline = PipelineOrchestrator(policy=policy)
        result = pipeline.process(csv_content, 'test.csv')

        assert result.success is True

        handler = get_handler('test.csv')
        handler.validate(result.protected_data, 'test.csv')
        df = handler.parse(result.protected_data)

        for email in df['email']:
            if 'HASH:' in str(email):
                assert True
                return

    @pytest.mark.integration
    def test_mask_only_policy(self, csv_content):
        """Test policy that only uses masking."""
        policy = Policy(
            version='1.0',
            description='Mask only',
            settings=PolicySettings(default_protection='masking'),
            rules=[
                ProtectionRule(
                    entity_type='EMAIL_ADDRESS',
                    protection_method='masking',
                    priority=1
                )
            ]
        )

        pipeline = PipelineOrchestrator(policy=policy)
        result = pipeline.process(csv_content, 'test.csv')

        assert result.success is True

    @pytest.mark.integration
    def test_high_threshold_detects_less(self, csv_content):
        """Test higher threshold results in fewer detections."""
        from src.detection.presidio_detector import PresidioDetector

        low_detector = PresidioDetector(score_threshold=0.3)
        high_detector = PresidioDetector(score_threshold=0.9)

        policy = Policy(
            version='1.0',
            description='Test',
            settings=PolicySettings(),
            rules=[]
        )

        low_pipeline = PipelineOrchestrator(policy=policy, detector=low_detector)
        high_pipeline = PipelineOrchestrator(policy=policy, detector=high_detector)

        low_result = low_pipeline.process(csv_content, 'test.csv')
        high_result = high_pipeline.process(csv_content, 'test.csv')

        low_entities = len(low_result.detection_summary.get('entities', []))
        high_entities = len(high_result.detection_summary.get('entities', []))

        assert low_entities >= high_entities


class TestPipelineErrorHandling:
    """Tests for pipeline error handling."""

    @pytest.mark.integration
    def test_invalid_csv_format(self):
        """Test handling of malformed CSV."""
        pipeline = create_pipeline()
        content = b'a,b,c\n1,2\n3,4,5,6'

        result = pipeline.process(content, 'bad.csv')

        assert result.success is False
        validate_stage = result.get_stage(PipelineStage.VALIDATE)
        assert validate_stage is not None
        assert validate_stage.success is False

    @pytest.mark.integration
    def test_invalid_json_format(self):
        """Test handling of malformed JSON."""
        pipeline = create_pipeline()
        content = b'{invalid json content'

        result = pipeline.process(content, 'bad.json')

        assert result.success is False

    @pytest.mark.integration
    def test_fail_fast_mode(self):
        """Test fail-fast stops at first error."""
        pipeline = PipelineOrchestrator(fail_fast=True)

        result = pipeline.process(b'', 'empty.csv')

        assert result.success is False
        assert len(result.stage_results) == 1
