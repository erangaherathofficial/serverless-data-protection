"""Unit tests for schema validation."""

import pandas as pd
import pytest

from src.validation.schema_validator import (
    SchemaInfo,
    SchemaValidator,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)


class TestSchemaInfo:
    """Tests for SchemaInfo dataclass."""

    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John', 'Jane', None],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
            'score': [85.5, 92.0, 78.5],
        })

    def test_from_dataframe(self, sample_df):
        schema = SchemaInfo.from_dataframe(sample_df)

        assert schema.columns == ['id', 'name', 'email', 'score']
        assert schema.row_count == 3
        assert 'int64' in schema.dtypes['id']
        assert schema.nullable['name'] is True
        assert schema.nullable['email'] is False


class TestValidationResult:
    """Tests for ValidationResult."""

    def test_empty_result_is_valid(self):
        result = ValidationResult(is_valid=True)
        assert result.is_valid is True
        assert len(result.issues) == 0

    def test_add_error_invalidates(self):
        result = ValidationResult(is_valid=True)
        result.add_error("Test error")
        assert result.is_valid is False
        assert len(result.errors) == 1

    def test_add_warning_keeps_valid(self):
        result = ValidationResult(is_valid=True)
        result.add_warning("Test warning")
        assert result.is_valid is True
        assert len(result.warnings) == 1

    def test_add_info(self):
        result = ValidationResult(is_valid=True)
        result.add_info("Test info", column="test_col")
        assert result.is_valid is True
        assert len(result.issues) == 1
        assert result.issues[0].column == "test_col"


class TestSchemaValidator:
    """Tests for SchemaValidator."""

    @pytest.fixture
    def original_df(self):
        return pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John', 'Jane', 'Bob'],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
        })

    @pytest.fixture
    def validator(self):
        return SchemaValidator()

    def test_identical_schemas_valid(self, validator, original_df):
        result = validator.validate(original_df, original_df.copy())
        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_missing_column_error(self, validator, original_df):
        result = validator.validate(
            original_df, original_df.drop(columns=['email'])
        )
        assert result.is_valid is False
        assert any('email' in e.message for e in result.errors)

    def test_extra_column_warning(self, validator, original_df):
        protected = original_df.copy()
        protected['extra'] = 'value'
        result = validator.validate(original_df, protected)
        assert result.is_valid is True
        assert any('extra' in w.message for w in result.warnings)

    def test_row_count_mismatch_error(self, validator, original_df):
        result = validator.validate(original_df, original_df.iloc[:2].copy())
        assert result.is_valid is False
        assert any('Row count' in e.message for e in result.errors)

    def test_type_widening_allowed_by_default(self, original_df):
        result = SchemaValidator().validate(
            original_df, original_df.astype(str)
        )
        assert result.is_valid is True

    def test_strict_type_checking_rejects_widening(self, original_df):
        validator = SchemaValidator(
            strict_types=True, allow_type_widening=False
        )
        result = validator.validate(original_df, original_df.astype(str))
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_xor_constructor_rejects_invalid_combinations(self):
        with pytest.raises(ValueError, match="strict_types"):
            SchemaValidator(strict_types=True, allow_type_widening=True)
        with pytest.raises(ValueError, match="strict_types"):
            SchemaValidator(strict_types=False, allow_type_widening=False)

    def test_column_order_change_warning(self, validator, original_df):
        protected = original_df[['email', 'name', 'id']]
        result = validator.validate(original_df, protected)
        assert result.is_valid is True
        assert any('order' in w.message.lower() for w in result.warnings)

    def test_null_introduced_warning(self, validator, original_df):
        protected = original_df.copy()
        protected.loc[0, 'name'] = None
        result = validator.validate(original_df, protected)
        assert any('null' in w.message.lower() for w in result.warnings)

    def test_validate_without_row_count(self, original_df):
        validator = SchemaValidator(validate_row_count=False)
        result = validator.validate(original_df, original_df.iloc[:2].copy())
        assert result.is_valid is True


class TestValidationIssue:
    """Tests for ValidationIssue."""

    def test_create_issue(self):
        issue = ValidationIssue(
            message="Test message",
            severity=ValidationSeverity.ERROR,
            column="test_col",
            details={'key': 'value'},
        )
        assert issue.message == "Test message"
        assert issue.severity == ValidationSeverity.ERROR
        assert issue.column == "test_col"


class TestProtectionRoundTrip:
    """End-to-end schema-preservation scenarios."""

    def test_redaction_preserves_schema(self):
        original = pd.DataFrame({
            'id': [1, 2, 3],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
            'ssn': ['123-45-6789', '987-65-4321', '555-55-5555'],
        })
        protected = original.copy()
        protected['email'] = protected['email'].apply(
            lambda v: f"HASH:{hash(v)}"
        )
        protected['ssn'] = '***-**-' + protected['ssn'].str[-4:]

        result = SchemaValidator().validate(original, protected)
        assert result.is_valid is True
        assert result.original_schema.row_count == 3
        assert result.protected_schema.row_count == 3

    def test_numeric_to_string_widening_accepted(self):
        original = pd.DataFrame({
            'id': [1, 2, 3],
            'amount': [100.50, 200.75, 300.00],
        })
        protected = original.copy()
        protected['amount'] = protected['amount'].apply(lambda v: f"ENC:{v}")

        result = SchemaValidator().validate(original, protected)
        assert result.is_valid is True
