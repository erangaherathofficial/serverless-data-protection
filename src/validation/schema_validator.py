"""Schema validation for data protection pipeline."""

import pandas as pd
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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


@dataclass
class SchemaInfo:
    """Schema information for a DataFrame."""

    columns: list[str]
    dtypes: dict[str, str]
    nullable: dict[str, bool]
    row_count: int

    @classmethod
    def from_dataframe(cls, df: pd.DataFrame) -> 'SchemaInfo':
        """Extract schema from a DataFrame."""
        return cls(
            columns=list(df.columns),
            dtypes={col: str(dtype) for col, dtype in df.dtypes.items()},
            nullable={col: bool(df[col].isna().any()) for col in df.columns},
            row_count=len(df),
        )


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
        return [
            i for i in self.issues
            if i.severity == ValidationSeverity.ERROR
        ]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Get warning issues only."""
        return [
            i for i in self.issues
            if i.severity == ValidationSeverity.WARNING
        ]


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
            strict_types: Require exact type matches.
            allow_type_widening: Allow string conversion (post-protection).
                Mutually exclusive with `strict_types`; both off would silently
                ignore every dtype change, both on would render widening dead.
            validate_row_count: Check row counts match.
        """
        if strict_types == allow_type_widening:
            raise ValueError(
                "Exactly one of strict_types and allow_type_widening must be "
                "True; got strict_types=allow_type_widening="
                f"{strict_types}."
            )
        self._strict_types = strict_types
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
            common_cols = [
                c for c in original.columns if c in protected.columns
            ]
            protected_order = [
                c for c in protected.columns if c in original.columns
            ]

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

            details = {
                'original_type': orig_dtype,
                'protected_type': prot_dtype,
            }

            if self._strict_types:
                result.add_error(
                    f"Type mismatch for '{col}': {orig_dtype} -> {prot_dtype}",
                    column=col,
                    details=details,
                )
            elif self._is_valid_type_conversion(orig_dtype, prot_dtype):
                result.add_info(
                    f"Type widened for '{col}': {orig_dtype} -> {prot_dtype}",
                    column=col,
                    details=details,
                )
            else:
                result.add_warning(
                    f"Unexpected type change for '{col}': "
                    f"{orig_dtype} -> {prot_dtype}",
                    column=col,
                    details=details,
                )

    def _validate_rows(
            self,
            original: SchemaInfo,
            protected: SchemaInfo,
            result: ValidationResult
    ) -> None:
        """Validate row count matches."""
        if original.row_count != protected.row_count:
            msg = (
                f"Row count mismatch: {original.row_count} "
                f"-> {protected.row_count}"
            )
            result.add_error(
                msg,
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

    _STRING_DTYPES = {'object', 'string'}
    _NUMERIC_DTYPES = {
        'int8', 'int16', 'int32', 'int64',
        'uint8', 'uint16', 'uint32', 'uint64',
        'Int8', 'Int16', 'Int32', 'Int64',
        'UInt8', 'UInt16', 'UInt32', 'UInt64',
        'float16', 'float32', 'float64',
        'Float32', 'Float64',
    }
    _BOOL_DTYPES = {'bool', 'boolean'}

    def _is_valid_type_conversion(self, from_type: str, to_type: str) -> bool:
        """Check if a dtype change is an acceptable widening.

        Accepted: non-bool ``→`` string-family (the canonical PII-redaction
        case), or numeric ``→`` numeric within the int/float family. The
        ``pd.StringDtype`` ``string[pyarrow]`` representation is handled by
        prefix match. Boolean ``→`` string is rejected as it usually
        indicates an unintended conversion rather than deliberate widening.
        """
        is_string_target = (
                to_type in self._STRING_DTYPES or to_type.startswith('string[')
        )
        if is_string_target and from_type not in self._BOOL_DTYPES:
            return True
        if from_type in self._NUMERIC_DTYPES and to_type in self._NUMERIC_DTYPES:
            return True
        return False
