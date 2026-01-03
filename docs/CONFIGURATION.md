# Configuration Guide

This document describes how to configure the serverless data protection framework.

## Environment Variables

The Lambda function supports the following environment variables:

| Variable              | Description                                 | Default                           |
|-----------------------|---------------------------------------------|-----------------------------------|
| `POLICY_BUCKET`       | S3 bucket containing policy files           | -                                 |
| `POLICY_KEY`          | S3 key for policy YAML file                 | `policies/protection_policy.yaml` |
| `SECURE_BUCKET`       | Destination bucket for protected data       | -                                 |
| `AUDIT_TABLE_NAME`    | DynamoDB table for audit records            | -                                 |
| `ENCRYPTION_KEY_ID`   | KMS key ID for AES-256 encryption           | -                                 |
| `LOG_LEVEL`           | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO`                            |
| `DETECTION_THRESHOLD` | Minimum confidence score for PII detection  | `0.5`                             |

## Policy Configuration

Policies are defined in YAML format and control how PII is detected and protected.

### Policy Structure

```yaml
version: "1.0"
settings:
  detection_threshold: 0.5
  enable_audit: true
  default_protection: masking

rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
    options:
      salt: "optional-salt"

  - entity_type: CREDIT_CARD
    protection_method: aes256_encrypt
    options:
      key_id: "aws/kms/key-id"

  - entity_type: PHONE_NUMBER
    protection_method: masking
    options:
      mask_char: "*"
      visible_chars: 4
```

### Supported Entity Types

Standard Presidio entities:

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`
- `CREDIT_CARD`
- `PERSON`
- `LOCATION`
- `DATE_TIME`
- `IP_ADDRESS`
- `IBAN_CODE`

UK-specific custom entities:

- `UK_NHS` - NHS numbers
- `UK_NINO` - National Insurance numbers
- `UK_POSTCODE` - UK postal codes
- `UK_PHONE` - UK phone numbers
- `UK_DRIVERS_LICENSE` - UK driving licence numbers
- `UK_PASSPORT` - UK passport numbers
- `UK_BANK_ACCOUNT` - UK bank account numbers
- `UK_VRN` - UK vehicle registration numbers

### Protection Methods

#### AES-256 Encryption (`aes256_encrypt`)

Reversible encryption using AES-256-CBC.

Options:

- `key_id`: AWS KMS key ID (optional, uses local key if not provided)

Output format: `ENC:{base64_encoded_data}`

#### SHA-256 Hashing (`sha256_hash`)

One-way cryptographic hash.

Options:

- `salt`: Optional salt value for the hash
- `algorithm`: `sha256` (default) or `sha512`

Output format: `HASH:{hex_digest}`

#### Masking (`masking`)

Partial character replacement.

Options:

- `mask_char`: Character to use for masking (default: `*`)
- `visible_chars`: Number of visible characters at start and end (default: 4)

Example: `john.smith@example.com` -> `john****@example.com`

#### Tokenization (`tokenization`)

Replace with surrogate values.

Options:

- `format`: `uuid` (default), `sequential`, or `format_preserving`
- `reversible`: Whether to store mapping in vault (default: `true`)

Output format: `TOKEN:{uuid}`

### Rule Priorities

Rules are evaluated in order. The first matching rule is applied. Use specific rules before general ones:

```yaml
rules:
  # Specific rule for financial emails
  - entity_type: EMAIL_ADDRESS
    column_pattern: ".*financial.*"
    protection_method: aes256_encrypt

  # General rule for all other emails
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
```

### Column-Based Rules

Target specific columns using patterns:

```yaml
rules:
  - entity_type: PERSON
    column_pattern: "^(name|full_name|customer_name)$"
    protection_method: masking
```

## CloudFormation Parameters

The SAM template accepts these parameters:

| Parameter            | Description                                 | Default |
|----------------------|---------------------------------------------|---------|
| `Environment`        | Deployment environment (dev, staging, prod) | `dev`   |
| `SourceBucketName`   | Source S3 bucket name                       | -       |
| `SecureBucketName`   | Destination S3 bucket name                  | -       |
| `PolicyBucketName`   | Policy files bucket                         | -       |
| `AuditRetentionDays` | DynamoDB TTL in days                        | `90`    |
| `LambdaMemorySize`   | Lambda memory in MB                         | `512`   |
| `LambdaTimeout`      | Lambda timeout in seconds                   | `300`   |

## File Format Configuration

### CSV Options

The CSV handler automatically detects:

- Delimiter (comma, semicolon, tab, pipe)
- Encoding (UTF-8, Latin-1, etc.)
- Quote character

### JSON Options

Supported JSON structures:

- Array of objects: `[{...}, {...}]`
- Records wrapper: `{"records": [{...}]}`
- Nested objects: `{"data": {"customers": [...]}}`
- Newline-delimited JSON (NDJSON)

### Parquet Options

Parquet files are processed using PyArrow with automatic schema detection.

## Audit Configuration

### CloudWatch Metrics

Metrics are published to the `DataProtection` namespace:

- `ProcessingStarted` - Count of processing jobs started
- `ProcessingCompleted` - Count of successful completions
- `ProcessingDuration` - Processing time in milliseconds
- `EntitiesDetected` - Count of PII entities found
- `ProtectionsApplied` - Count of protection operations
- `ProcessingErrors` - Count of errors

### DynamoDB Audit Table

The audit table uses a single-table design:

**Primary Key:**

- `pk`: Partition key (e.g., `FILE#bucket/key`)
- `sk`: Sort key (e.g., `PROCESS#timestamp`)

**GSI1:**

- `gsi1pk`: Date partition (e.g., `DATE#2024-01-15`)
- `gsi1sk`: File identifier

Record types:

- `PROCESS#` - Processing activity records
- `DETECTION#` - PII detection results
- `PROTECTION#` - Protection action records
- `ENTITY#` - Individual entity records (optional)

## Detection Threshold Tuning

Adjust the detection threshold based on your accuracy requirements:

| Threshold | Precision | Recall   | Use Case                                  |
|-----------|-----------|----------|-------------------------------------------|
| 0.3       | Lower     | Higher   | Maximum detection, accept false positives |
| 0.5       | Balanced  | Balanced | General use (recommended)                 |
| 0.7       | Higher    | Lower    | Minimize false positives                  |
| 0.9       | Highest   | Lowest   | Only high-confidence detections           |

## Performance Tuning

### Lambda Memory

Memory affects both available RAM and CPU allocation:

- 512MB: Suitable for files up to 10MB
- 1024MB: Suitable for files up to 50MB
- 2048MB: Suitable for files up to 100MB

### Timeout

Set timeout based on expected file sizes:

- Small files (<1MB): 30 seconds
- Medium files (1-10MB): 60 seconds
- Large files (10-100MB): 300 seconds
