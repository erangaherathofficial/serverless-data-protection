# API Reference

This document describes the internal APIs and interfaces of the data protection framework.

## Lambda Handler

### Entry Point

```python
from src.lambda_handler import lambda_handler

def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """Process S3 event and protect PII data.

    Args:
        event: S3 event notification
        context: Lambda context object

    Returns:
        Processing result dictionary
    """
```

### Event Format

```json
{
  "Records": [
    {
      "s3": {
        "bucket": {"name": "source-bucket"},
        "object": {"key": "path/to/file.csv"}
      }
    }
  ]
}
```

### Response Format

```json
{
  "statusCode": 200,
  "body": {
    "request_id": "uuid",
    "source_key": "path/to/file.csv",
    "secure_key": "protected/path/to/file.csv",
    "success": true,
    "duration_ms": 1234.56,
    "detection_summary": {
      "entities_found": 15,
      "entity_types": {"EMAIL_ADDRESS": 10, "PHONE_NUMBER": 5}
    },
    "protection_summary": {
      "protections_applied": 15
    }
  }
}
```

## Pipeline Orchestrator

### Creating a Pipeline

```python
from src.pipeline.pipeline_orchestrator import create_pipeline, PipelineOrchestrator

# Quick creation with defaults
pipeline = create_pipeline()

# Custom configuration
from src.detection.presidio_detector import PresidioDetector
from src.policy.policy_parser import PolicyParser

pipeline = PipelineOrchestrator(
    detector=PresidioDetector(score_threshold=0.5),
    policy_parser=PolicyParser()
)
```

### Processing Data

```python
# Process raw bytes
result = pipeline.process(
    data=file_bytes,
    file_name="data.csv",
    policy=policy_object  # Optional, uses default if not provided
)

# Access results
if result.success:
    protected_bytes = result.protected_data
    detection_info = result.detection_summary
    protection_info = result.protection_summary
else:
    error = result.errors
```

### Pipeline Result

```python
@dataclass
class PipelineResult:
    success: bool
    protected_data: bytes | None
    original_format: str
    detection_summary: dict | None
    protection_summary: dict | None
    schema_preserved: bool
    stage_durations: dict[str, float]
    total_duration_ms: float
    errors: list[str]
```

## File Handlers

### Handler Factory

```python
from src.handlers.handler_factory import HandlerFactory

# Get handler by filename
handler = HandlerFactory.get_handler("data.csv")

# Get handler by extension
handler = HandlerFactory.get_handler_by_extension(".json")

# List supported formats
formats = HandlerFactory.get_supported_formats()
# Returns: ['.csv', '.json', '.parquet']
```

### Handler Interface

All handlers implement `BaseHandler`:

```python
from src.handlers.base_handler import BaseHandler

class CustomHandler(BaseHandler):
    def validate(self, content: bytes, filename: str) -> bool:
        """Validate file format."""
        pass

    def parse(self, content: bytes) -> pd.DataFrame:
        """Parse content to DataFrame."""
        pass

    def serialize(self, df: pd.DataFrame) -> bytes:
        """Serialize DataFrame back to format."""
        pass

    def detect_encoding(self, content: bytes) -> str:
        """Detect file encoding."""
        pass
```

### CSV Handler

```python
from src.handlers.csv_handler import CSVHandler

handler = CSVHandler()

# Validate CSV
is_valid = handler.validate(content, "data.csv")

# Parse to DataFrame
df = handler.parse(content)

# Serialize back to CSV
output = handler.serialize(df)
```

### JSON Handler

```python
from src.handlers.json_handler import JSONHandler

handler = JSONHandler()

# Handles multiple JSON structures:
# - Array: [{"key": "value"}, ...]
# - Records: {"records": [...]}
# - Nested: {"data": {"items": [...]}}
# - NDJSON: {"key": "value"}\n{"key": "value"}
```

### Parquet Handler

```python
from src.handlers.parquet_handler import ParquetHandler

handler = ParquetHandler()

# Uses PyArrow for efficient processing
df = handler.parse(parquet_bytes)
output = handler.serialize(df)
```

## PII Detection

### Presidio Detector

```python
from src.detection.presidio_detector import PresidioDetector

detector = PresidioDetector(
    score_threshold=0.5,
    entities=None,  # Detect all by default
    language='en'
)

# Detect in text
entities = detector.detect_text("john@example.com")

# Detect in DataFrame
result = detector.detect_dataframe(df)

# Result contains:
# - entities_by_column: dict[str, list[PIIEntity]]
# - total_entities: int
# - columns_with_pii: list[str]
```

### PIIEntity

```python
@dataclass
class PIIEntity:
    entity_type: str
    start: int
    end: int
    score: float
    text: str
    column: str | None
    row_index: int | None
```

### Custom Recognizers

```python
from src.detection.custom_recognizers import (
    UKNHSRecognizer,
    UKNINORecognizer,
    UKPostcodeRecognizer,
    UKPhoneRecognizer,
    get_uk_recognizers
)

# Get all UK recognizers
recognizers = get_uk_recognizers()

# Add to detector
for recognizer in recognizers:
    detector.add_recognizer(recognizer)
```

## Policy Engine

### Loading Policies

```python
from src.policy.policy_parser import PolicyParser, Policy

parser = PolicyParser()

# Load from YAML string
policy = parser.parse(yaml_string)

# Load from file
policy = parser.load_from_file("policy.yaml")

# Load from S3
policy = parser.load_from_s3(bucket="bucket", key="policy.yaml")
```

### Policy Structure

```python
@dataclass
class Policy:
    version: str
    settings: PolicySettings
    rules: list[ProtectionRule]

@dataclass
class ProtectionRule:
    entity_type: str
    protection_method: str
    column_pattern: str | None
    options: dict
    priority: int
```

### Rule Evaluation

```python
from src.policy.rule_evaluator import RuleEvaluator

evaluator = RuleEvaluator(policy)

# Evaluate single entity
action = evaluator.evaluate_entity(entity)

# Evaluate all entities
result = evaluator.evaluate_all(entities)
```

### Protection Mapping

```python
from src.policy.protection_mapper import ProtectionMapper

mapper = ProtectionMapper(policy)

# Create protection plan for DataFrame
plan = mapper.create_plan(df, detection_result)

# Plan contains actions for each cell
for col_plan in plan.column_plans:
    for cell_action in col_plan.actions:
        # Apply protection
        pass
```

## Protection Strategies

### Strategy Registry

```python
from src.protection.base_protection import ProtectionRegistry

# Get strategy by name
strategy = ProtectionRegistry.get('sha256_hash')

# List available strategies
strategies = ProtectionRegistry.list_strategies()
# Returns: ['aes256_encrypt', 'sha256_hash', 'masking', ...]
```

### Using Strategies

```python
from src.protection import (
    AES256Encryption,
    SHA256Hashing,
    Masking,
    Tokenization
)

# AES-256 encryption
encryptor = AES256Encryption(key_id="aws/kms/key")
encrypted = encryptor.protect("sensitive data")
decrypted = encryptor.unprotect(encrypted)

# SHA-256 hashing
hasher = SHA256Hashing(salt="optional-salt")
hashed = hasher.protect("sensitive data")

# Masking
masker = Masking(mask_char='*', visible_chars=4)
masked = masker.protect("john@example.com")
# Returns: "john****@example.com"

# Tokenization
tokenizer = Tokenization(reversible=True)
token = tokenizer.protect("sensitive data")
original = tokenizer.unprotect(token)
```

### Custom Strategy

```python
from src.protection.base_protection import BaseProtection, register_protection

@register_protection('custom_method')
class CustomProtection(BaseProtection):
    def protect(self, value: str) -> str:
        # Implement protection logic
        return protected_value

    def unprotect(self, value: str) -> str:
        # Implement recovery logic (if reversible)
        return original_value

    @property
    def is_reversible(self) -> bool:
        return True
```

## Schema Validation

### Schema Validator

```python
from src.validation.schema_validator import SchemaValidator, SchemaInfo

validator = SchemaValidator()

# Extract schema
schema = validator.extract_schema(df)

# Validate against schema
is_valid, errors = validator.validate(df, schema)

# Compare schemas
diff = validator.compare_schemas(schema1, schema2)
```

### SchemaInfo

```python
@dataclass
class SchemaInfo:
    column_names: list[str]
    column_types: dict[str, str]
    row_count: int
    nullable_columns: list[str]
```

### Schema Enforcement

```python
from src.validation.schema_validator import SchemaEnforcer

enforcer = SchemaEnforcer()

# Enforce schema on DataFrame
df_enforced = enforcer.enforce(df, original_schema)
```

## Audit Trail

### CloudWatch Logger

```python
from src.audit.cloudwatch_logger import CloudWatchLogger, get_audit_logger

logger = get_audit_logger()

# Log processing start
logger.log_processing_start(
    request_id="uuid",
    file_name="data.csv",
    file_size=1024,
    file_format="CSV"
)

# Log detection results
logger.log_detection_results(
    request_id="uuid",
    file_name="data.csv",
    entities_found=15,
    entity_types={"EMAIL_ADDRESS": 10},
    columns_with_pii=["email"],
    duration_ms=50.0
)

# Log completion
logger.log_processing_complete(
    request_id="uuid",
    file_name="data.csv",
    duration_ms=1234.56,
    success=True
)
```

### DynamoDB Writer

```python
from src.audit.dynamodb_writer import DynamoDBWriter, get_audit_writer

writer = get_audit_writer()

# Write processing record
record_id = writer.write_processing_record(
    request_id="uuid",
    source_bucket="bucket",
    source_key="key",
    file_format="CSV",
    file_size=1024,
    success=True,
    duration_ms=1234.56
)

# Query records
records = writer.query_by_file(bucket="bucket", key="key")
records = writer.query_by_date(date="2024-01-15")

# Get statistics
stats = writer.get_processing_stats(days=7)
```

## AWS Client Manager

### Singleton Access

```python
from src.aws.client_manager import get_client_manager

manager = get_client_manager()

# Access clients
s3 = manager.s3_client
dynamodb = manager.dynamodb_client
kms = manager.kms_client

# Access resources
dynamodb_resource = manager.dynamodb_resource

# Read from S3
content = manager.read_s3_object(bucket="bucket", key="key")

# Write to S3
manager.write_s3_object(bucket="bucket", key="key", data=bytes_data)
```
