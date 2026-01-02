"""Schema validation for data protection pipeline."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    ERROR = 'error'
    WARNING = 'warning'
    INFO = 'info'


@dataclass
class ValidationIssue:
    """A single validation issue."""

    message: str
    severity: ValidationSeverity
    column: Optional[str] = None
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'message': self.message,
            'severity': self.severity.value,
            'column': self.column,
            'details': self.details
        }


@dataclass
class SchemaInfo:
    """Schema information for a DataFrame."""

    columns: list[str]
    dtypes: dict[str, str]
    nullable: dict[str, bool]
    row_count: int
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_dataframe(cls, df: pd.DataFrame) -> 'SchemaInfo':
        """Extract schema from DataFrame.

        Args:
            df: Source DataFrame

        Returns:
            SchemaInfo object
        """
        nullable = {}
        for col in df.columns:
            nullable[col] = df[col].isna().any()

        return cls(
            columns=list(df.columns),
            dtypes={col: str(dtype) for col, dtype in df.dtypes.items()},
            nullable=nullable,
            row_count=len(df)
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'columns': self.columns,
            'dtypes': self.dtypes,
            'nullable': self.nullable,
            'row_count': self.row_count,
            'metadata': self.metadata
        }


@dataclass
class ValidationResult:
    """Result of schema validation."""

    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    original_schema: Optional[SchemaInfo] = None
    protected_schema: Optional[SchemaInfo] = None

    def add_issue(self, issue: ValidationIssue) -> None:
        """Add validation issue."""
        self.issues.append(issue)
        if issue.severity == ValidationSeverity.ERROR:
            self.is_valid = False

    def add_error(self, message: str, column: Optional[str] = None,
                  details: Optional[dict] = None) -> None:
        """Add error issue."""
        self.add_issue(ValidationIssue(
            message=message,
            severity=ValidationSeverity.ERROR,
            column=column,
            details=details
        ))

    def add_warning(self, message: str, column: Optional[str] = None,
                    details: Optional[dict] = None) -> None:
        """Add warning issue."""
        self.add_issue(ValidationIssue(
            message=message,
            severity=ValidationSeverity.WARNING,
            column=column,
            details=details
        ))

    def add_info(self, message: str, column: Optional[str] = None,
                 details: Optional[dict] = None) -> None:
        """Add info issue."""
        self.add_issue(ValidationIssue(
            message=message,
            severity=ValidationSeverity.INFO,
            column=column,
            details=details
        ))

    @property
    def errors(self) -> list[ValidationIssue]:
        """Get error issues only."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Get warning issues only."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'is_valid': self.is_valid,
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
            'issues': [i.to_dict() for i in self.issues],
            'original_schema': self.original_schema.to_dict() if self.original_schema else None,
            'protected_schema': self.protected_schema.to_dict() if self.protected_schema else None
        }


class SchemaValidator:
    """Validates schema preservation after data protection.

    Ensures protected data maintains:
    - Same column names
    - Same column order
    - Compatible data types
    - Same row count
    - Nullable constraints
    """

    def __init__(
        self,
        strict_types: bool = False,
        allow_type_widening: bool = True,
        validate_row_count: bool = True
    ) -> None:
        """Initialize validator.

        Args:
            strict_types: Require exact type matches
            allow_type_widening: Allow string conversion (common after protection)
            validate_row_count: Check row counts match
        """
        self._strict_types = strict_types
        self._allow_type_widening = allow_type_widening
        self._validate_row_count = validate_row_count

    def validate(
        self,
        original: pd.DataFrame,
        protected: pd.DataFrame
    ) -> ValidationResult:
        """Validate protected DataFrame against original schema.

        Args:
            original: Original DataFrame before protection
            protected: DataFrame after protection

        Returns:
            ValidationResult with any issues found
        """
        original_schema = SchemaInfo.from_dataframe(original)
        protected_schema = SchemaInfo.from_dataframe(protected)

        result = ValidationResult(
            is_valid=True,
            original_schema=original_schema,
            protected_schema=protected_schema
        )

        self._validate_columns(original_schema, protected_schema, result)
        self._validate_column_order(original_schema, protected_schema, result)
        self._validate_dtypes(original_schema, protected_schema, result)

        if self._validate_row_count:
            self._validate_rows(original_schema, protected_schema, result)

        self._validate_nullable(original, protected, result)

        return result

    def _validate_columns(
        self,
        original: SchemaInfo,
        protected: SchemaInfo,
        result: ValidationResult
    ) -> None:
        """Validate column names match."""
        original_cols = set(original.columns)
        protected_cols = set(protected.columns)

        missing = original_cols - protected_cols
        extra = protected_cols - original_cols

        for col in missing:
            result.add_error(
                f"Column '{col}' missing in protected data",
                column=col,
                details={'type': 'missing_column'}
            )

        for col in extra:
            result.add_warning(
                f"Extra column '{col}' in protected data",
                column=col,
                details={'type': 'extra_column'}
            )

    def _validate_column_order(
        self,
        original: SchemaInfo,
        protected: SchemaInfo,
        result: ValidationResult
    ) -> None:
        """Validate column order is preserved."""
        if original.columns != protected.columns:
            common_cols = [c for c in original.columns if c in protected.columns]
            protected_order = [c for c in protected.columns if c in original.columns]

            if common_cols != protected_order:
                result.add_warning(
                    "Column order differs from original",
                    details={
                        'original_order': original.columns,
                        'protected_order': protected.columns
                    }
                )

    def _validate_dtypes(
        self,
        original: SchemaInfo,
        protected: SchemaInfo,
        result: ValidationResult
    ) -> None:
        """Validate data types are compatible."""
        for col in original.columns:
            if col not in protected.dtypes:
                continue

            orig_dtype = original.dtypes[col]
            prot_dtype = protected.dtypes[col]

            if orig_dtype == prot_dtype:
                continue

            if self._strict_types:
                result.add_error(
                    f"Type mismatch for '{col}': {orig_dtype} -> {prot_dtype}",
                    column=col,
                    details={
                        'original_type': orig_dtype,
                        'protected_type': prot_dtype
                    }
                )
            elif self._allow_type_widening:
                if self._is_valid_type_conversion(orig_dtype, prot_dtype):
                    result.add_info(
                        f"Type widened for '{col}': {orig_dtype} -> {prot_dtype}",
                        column=col,
                        details={
                            'original_type': orig_dtype,
                            'protected_type': prot_dtype
                        }
                    )
                else:
                    result.add_warning(
                        f"Unexpected type change for '{col}': {orig_dtype} -> {prot_dtype}",
                        column=col,
                        details={
                            'original_type': orig_dtype,
                            'protected_type': prot_dtype
                        }
                    )

    def _validate_rows(
        self,
        original: SchemaInfo,
        protected: SchemaInfo,
        result: ValidationResult
    ) -> None:
        """Validate row count matches."""
        if original.row_count != protected.row_count:
            result.add_error(
                f"Row count mismatch: {original.row_count} -> {protected.row_count}",
                details={
                    'original_rows': original.row_count,
                    'protected_rows': protected.row_count
                }
            )

    def _validate_nullable(
        self,
        original: pd.DataFrame,
        protected: pd.DataFrame,
        result: ValidationResult
    ) -> None:
        """Validate nullable constraints."""
        for col in original.columns:
            if col not in protected.columns:
                continue

            orig_has_null = original[col].isna().any()
            prot_has_null = protected[col].isna().any()

            if not orig_has_null and prot_has_null:
                result.add_warning(
                    f"Column '{col}' gained null values after protection",
                    column=col,
                    details={
                        'original_nulls': int(original[col].isna().sum()),
                        'protected_nulls': int(protected[col].isna().sum())
                    }
                )

    def _is_valid_type_conversion(self, from_type: str, to_type: str) -> bool:
        """Check if type conversion is acceptable.

        Common after protection: numeric/date -> string
        """
        string_types = {'object', 'string', 'str'}

        if to_type in string_types:
            return True

        numeric_types = {'int64', 'int32', 'float64', 'float32'}
        if from_type in numeric_types and to_type in numeric_types:
            return True

        return False


class SchemaEnforcer:
    """Enforces schema constraints on protected data."""

    def __init__(self, original_schema: SchemaInfo) -> None:
        """Initialize enforcer with original schema.

        Args:
            original_schema: Schema to enforce
        """
        self._schema = original_schema

    def enforce(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enforce schema on DataFrame.

        Args:
            df: DataFrame to enforce schema on

        Returns:
            DataFrame with enforced schema
        """
        result = df.copy()

        result = self._enforce_columns(result)
        result = self._enforce_order(result)

        return result

    def _enforce_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure all original columns exist."""
        for col in self._schema.columns:
            if col not in df.columns:
                df[col] = None
                logger.warning(f"Added missing column: {col}")

        extra_cols = set(df.columns) - set(self._schema.columns)
        if extra_cols:
            df = df.drop(columns=list(extra_cols))
            logger.warning(f"Removed extra columns: {extra_cols}")

        return df

    def _enforce_order(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enforce column order."""
        return df[self._schema.columns]


class SchemaComparator:
    """Compares schemas for differences."""

    @staticmethod
    def compare(
        schema1: SchemaInfo,
        schema2: SchemaInfo
    ) -> dict:
        """Compare two schemas and return differences.

        Args:
            schema1: First schema
            schema2: Second schema

        Returns:
            Dictionary of differences
        """
        differences = {
            'columns': {
                'added': [],
                'removed': [],
                'common': []
            },
            'types': {},
            'row_count': {
                'schema1': schema1.row_count,
                'schema2': schema2.row_count,
                'match': schema1.row_count == schema2.row_count
            }
        }

        cols1 = set(schema1.columns)
        cols2 = set(schema2.columns)

        differences['columns']['added'] = list(cols2 - cols1)
        differences['columns']['removed'] = list(cols1 - cols2)
        differences['columns']['common'] = list(cols1 & cols2)

        for col in differences['columns']['common']:
            type1 = schema1.dtypes.get(col)
            type2 = schema2.dtypes.get(col)
            if type1 != type2:
                differences['types'][col] = {
                    'from': type1,
                    'to': type2
                }

        return differences

    @staticmethod
    def are_compatible(
        schema1: SchemaInfo,
        schema2: SchemaInfo,
        strict: bool = False
    ) -> bool:
        """Check if two schemas are compatible.

        Args:
            schema1: First schema
            schema2: Second schema
            strict: Require exact match

        Returns:
            True if compatible
        """
        if set(schema1.columns) != set(schema2.columns):
            return False

        if strict:
            if schema1.columns != schema2.columns:
                return False
            if schema1.dtypes != schema2.dtypes:
                return False

        return True


def validate_schema(
    original: pd.DataFrame,
    protected: pd.DataFrame,
    strict: bool = False
) -> ValidationResult:
    """Convenience function to validate schema preservation.

    Args:
        original: Original DataFrame
        protected: Protected DataFrame
        strict: Use strict type checking

    Returns:
        ValidationResult
    """
    validator = SchemaValidator(strict_types=strict)
    return validator.validate(original, protected)


def extract_schema(df: pd.DataFrame) -> SchemaInfo:
    """Extract schema from DataFrame.

    Args:
        df: Source DataFrame

    Returns:
        SchemaInfo object
    """
    return SchemaInfo.from_dataframe(df)
