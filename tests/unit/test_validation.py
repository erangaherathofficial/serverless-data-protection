"""Unit tests for schema validation."""

import pandas as pd
import pytest

from src.validation.schema_validator import (
    SchemaComparator,
    SchemaEnforcer,
    SchemaInfo,
    SchemaValidator,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
    extract_schema,
    validate_schema,
)


class TestSchemaInfo:
    """Tests for SchemaInfo dataclass."""

    @pytest.fixture
    def sample_df(self):
        """Create sample DataFrame."""
        return pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John', 'Jane', None],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
            'score': [85.5, 92.0, 78.5]
        })

    def test_from_dataframe(self, sample_df):
        """Test schema extraction from DataFrame."""
        schema = SchemaInfo.from_dataframe(sample_df)

        assert schema.columns == ['id', 'name', 'email', 'score']
        assert schema.row_count == 3
        assert 'int64' in schema.dtypes['id']
        # Use bool() for numpy bool compatibility
        assert bool(schema.nullable['name']) is True
        assert bool(schema.nullable['email']) is False

    def test_to_dict(self, sample_df):
        """Test schema serialization."""
        schema = SchemaInfo.from_dataframe(sample_df)
        data = schema.to_dict()

        assert 'columns' in data
        assert 'dtypes' in data
        assert 'nullable' in data
        assert 'row_count' in data

    def test_extract_schema_function(self, sample_df):
        """Test convenience function."""
        schema = extract_schema(sample_df)
        assert isinstance(schema, SchemaInfo)
        assert len(schema.columns) == 4


class TestValidationResult:
    """Tests for ValidationResult."""

    def test_empty_result_is_valid(self):
        """Test empty result is valid."""
        result = ValidationResult(is_valid=True)
        assert result.is_valid is True
        assert len(result.issues) == 0

    def test_add_error_invalidates(self):
        """Test adding error invalidates result."""
        result = ValidationResult(is_valid=True)
        result.add_error("Test error")

        assert result.is_valid is False
        assert len(result.errors) == 1

    def test_add_warning_keeps_valid(self):
        """Test adding warning keeps result valid."""
        result = ValidationResult(is_valid=True)
        result.add_warning("Test warning")

        assert result.is_valid is True
        assert len(result.warnings) == 1

    def test_add_info(self):
        """Test adding info message."""
        result = ValidationResult(is_valid=True)
        result.add_info("Test info", column="test_col")

        assert result.is_valid is True
        assert len(result.issues) == 1
        assert result.issues[0].column == "test_col"

    def test_to_dict(self):
        """Test result serialization."""
        result = ValidationResult(is_valid=True)
        result.add_error("Error 1")
        result.add_warning("Warning 1")

        data = result.to_dict()
        assert data['is_valid'] is False
        assert data['error_count'] == 1
        assert data['warning_count'] == 1


class TestSchemaValidator:
    """Tests for SchemaValidator."""

    @pytest.fixture
    def original_df(self):
        """Create original DataFrame."""
        return pd.DataFrame({
            'id': [1, 2, 3],
            'name': ['John', 'Jane', 'Bob'],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com']
        })

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return SchemaValidator()

    def test_identical_schemas_valid(self, validator, original_df):
        """Test identical schemas pass validation."""
        protected = original_df.copy()
        result = validator.validate(original_df, protected)

        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_missing_column_error(self, validator, original_df):
        """Test missing column causes error."""
        protected = original_df.drop(columns=['email'])
        result = validator.validate(original_df, protected)

        assert result.is_valid is False
        assert any('email' in e.message for e in result.errors)

    def test_extra_column_warning(self, validator, original_df):
        """Test extra column causes warning."""
        protected = original_df.copy()
        protected['extra'] = 'value'
        result = validator.validate(original_df, protected)

        assert result.is_valid is True
        assert any('extra' in w.message for w in result.warnings)

    def test_row_count_mismatch_error(self, validator, original_df):
        """Test row count mismatch causes error."""
        protected = original_df.iloc[:2].copy()
        result = validator.validate(original_df, protected)

        assert result.is_valid is False
        assert any('Row count' in e.message for e in result.errors)

    def test_type_change_with_widening(self, original_df):
        """Test type widening is allowed by default."""
        validator = SchemaValidator(allow_type_widening=True)
        protected = original_df.astype(str)
        result = validator.validate(original_df, protected)

        assert result.is_valid is True

    def test_strict_type_checking(self, original_df):
        """Test strict type checking fails on type change."""
        validator = SchemaValidator(strict_types=True)
        protected = original_df.astype(str)
        result = validator.validate(original_df, protected)

        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_column_order_change_warning(self, validator, original_df):
        """Test column order change causes warning."""
        protected = original_df[['email', 'name', 'id']]
        result = validator.validate(original_df, protected)

        assert result.is_valid is True
        assert any('order' in w.message.lower() for w in result.warnings)

    def test_null_introduced_warning(self, validator, original_df):
        """Test introduced nulls cause warning."""
        protected = original_df.copy()
        protected.loc[0, 'name'] = None
        result = validator.validate(original_df, protected)

        assert any('null' in w.message.lower() for w in result.warnings)

    def test_validate_without_row_count(self, original_df):
        """Test validation without row count check."""
        validator = SchemaValidator(validate_row_count=False)
        protected = original_df.iloc[:2].copy()
        result = validator.validate(original_df, protected)

        assert result.is_valid is True

    def test_convenience_function(self, original_df):
        """Test validate_schema convenience function."""
        protected = original_df.copy()
        result = validate_schema(original_df, protected)

        assert isinstance(result, ValidationResult)
        assert result.is_valid is True


class TestSchemaEnforcer:
    """Tests for SchemaEnforcer."""

    @pytest.fixture
    def original_schema(self):
        """Create original schema."""
        return SchemaInfo(
            columns=['id', 'name', 'email'],
            dtypes={'id': 'int64', 'name': 'object', 'email': 'object'},
            nullable={'id': False, 'name': True, 'email': False},
            row_count=3
        )

    def test_enforce_missing_column(self, original_schema):
        """Test enforcer adds missing columns."""
        enforcer = SchemaEnforcer(original_schema)
        df = pd.DataFrame({
            'id': [1, 2],
            'name': ['John', 'Jane']
        })

        result = enforcer.enforce(df)
        assert 'email' in result.columns

    def test_enforce_extra_column_removed(self, original_schema):
        """Test enforcer removes extra columns."""
        enforcer = SchemaEnforcer(original_schema)
        df = pd.DataFrame({
            'id': [1],
            'name': ['John'],
            'email': ['john@test.com'],
            'extra': ['value']
        })

        result = enforcer.enforce(df)
        assert 'extra' not in result.columns

    def test_enforce_column_order(self, original_schema):
        """Test enforcer restores column order."""
        enforcer = SchemaEnforcer(original_schema)
        df = pd.DataFrame({
            'email': ['john@test.com'],
            'id': [1],
            'name': ['John']
        })

        result = enforcer.enforce(df)
        assert list(result.columns) == ['id', 'name', 'email']


class TestSchemaComparator:
    """Tests for SchemaComparator."""

    @pytest.fixture
    def schema1(self):
        """Create first schema."""
        return SchemaInfo(
            columns=['id', 'name', 'email'],
            dtypes={'id': 'int64', 'name': 'object', 'email': 'object'},
            nullable={'id': False, 'name': True, 'email': False},
            row_count=10
        )

    @pytest.fixture
    def schema2(self):
        """Create second schema with differences."""
        return SchemaInfo(
            columns=['id', 'name', 'phone'],
            dtypes={'id': 'int64', 'name': 'string', 'phone': 'object'},
            nullable={'id': False, 'name': True, 'phone': False},
            row_count=10
        )

    def test_compare_schemas(self, schema1, schema2):
        """Test schema comparison."""
        diff = SchemaComparator.compare(schema1, schema2)

        assert 'email' in diff['columns']['removed']
        assert 'phone' in diff['columns']['added']
        assert 'id' in diff['columns']['common']
        assert 'name' in diff['types']

    def test_compare_identical_schemas(self, schema1):
        """Test comparing identical schemas."""
        diff = SchemaComparator.compare(schema1, schema1)

        assert len(diff['columns']['added']) == 0
        assert len(diff['columns']['removed']) == 0
        assert len(diff['types']) == 0

    def test_are_compatible(self, schema1):
        """Test compatibility check for identical schemas."""
        assert SchemaComparator.are_compatible(schema1, schema1) is True

    def test_are_compatible_different_columns(self, schema1, schema2):
        """Test compatibility check with different columns."""
        assert SchemaComparator.are_compatible(schema1, schema2) is False

    def test_are_compatible_strict(self, schema1):
        """Test strict compatibility check."""
        schema_reordered = SchemaInfo(
            columns=['name', 'id', 'email'],
            dtypes=schema1.dtypes,
            nullable=schema1.nullable,
            row_count=schema1.row_count
        )

        assert SchemaComparator.are_compatible(
            schema1, schema_reordered, strict=False
        ) is True
        assert SchemaComparator.are_compatible(
            schema1, schema_reordered, strict=True
        ) is False


class TestValidationIssue:
    """Tests for ValidationIssue."""

    def test_create_issue(self):
        """Test creating validation issue."""
        issue = ValidationIssue(
            message="Test message",
            severity=ValidationSeverity.ERROR,
            column="test_col",
            details={'key': 'value'}
        )

        assert issue.message == "Test message"
        assert issue.severity == ValidationSeverity.ERROR
        assert issue.column == "test_col"

    def test_to_dict(self):
        """Test issue serialization."""
        issue = ValidationIssue(
            message="Test",
            severity=ValidationSeverity.WARNING
        )
        data = issue.to_dict()

        assert data['message'] == "Test"
        assert data['severity'] == 'warning'


class TestIntegration:
    """Integration tests for schema validation."""

    def test_protection_scenario(self):
        """Test typical protection scenario."""
        original = pd.DataFrame({
            'id': [1, 2, 3],
            'email': ['john@test.com', 'jane@test.com', 'bob@test.com'],
            'ssn': ['123-45-6789', '987-65-4321', '555-55-5555']
        })

        protected = original.copy()
        protected['email'] = protected['email'].apply(
            lambda x: f"HASH:{hash(x)}"
        )
        protected['ssn'] = '***-**-' + protected['ssn'].str[-4:]

        result = validate_schema(original, protected)

        assert result.is_valid is True
        assert result.original_schema.row_count == 3
        assert result.protected_schema.row_count == 3

    def test_protection_with_type_change(self):
        """Test protection that changes types."""
        original = pd.DataFrame({
            'id': [1, 2, 3],
            'amount': [100.50, 200.75, 300.00]
        })

        protected = original.copy()
        protected['amount'] = protected['amount'].apply(
            lambda x: f"ENC:{x}"
        )

        validator = SchemaValidator(allow_type_widening=True)
        result = validator.validate(original, protected)

        assert result.is_valid is True
