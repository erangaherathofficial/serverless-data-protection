# Configuration Guide

This document describes how to configure the serverless data protection framework.

## Environment Variables

The Lambda function supports the following environment variables:

| Variable             | Description                                    | Default     |
|----------------------|------------------------------------------------|-------------|
| `AWS_REGION`         | AWS region for all service clients             | `us-east-1` |
| `RAW_BUCKET_NAME`    | S3 bucket receiving uploaded source files      | -           |
| `SECURE_BUCKET_NAME` | S3 bucket for protected output                 | -           |
| `AUDIT_TABLE_NAME`   | DynamoDB table for audit records               | -           |
| `KMS_KEY_ID`         | KMS key id used by AES-256 encryption strategy | -           |
| `LOG_LEVEL`          | Python logging level                           | `INFO`      |

## Policy Configuration

Policies are defined in YAML format and control how PII is detected and protected.

### Policy Structure

```yaml
version: "1.0"
settings:
  confidence_threshold: 0.7
  default_protection: masking

rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
    priority: 1

  - entity_type: CREDIT_CARD
    protection_method: aes256_encrypt
    priority: 1

  - entity_type: PHONE_NUMBER
    protection_method: masking
    priority: 2
    options:
      mask_char: "*"
      visible_chars: 4
      direction: right
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
- `UK_NAME` - Common UK first/last names
- `UK_CITY` - Major UK cities and towns
- `UK_DRIVERS_LICENSE` - UK driving licence numbers
- `UK_PASSPORT` - UK passport numbers
- `UK_BANK_ACCOUNT` - UK bank account numbers
- `UK_VRN` - UK vehicle registration numbers

### Protection Methods

The YAML `options:` block recognises four fields parsed by
`ProtectionOptions.from_dict`: `mask_char`, `visible_chars`, `direction`,
and `token_prefix`. Unknown keys are silently dropped.

#### AES-256 Encryption (`aes256_encrypt`)

Reversible encryption using AES-256-CBC with PKCS7 padding. The data key
defaults to a per-container random key, which is appropriate for
write-only workflows. To make ciphertext portable across cold starts,
either set the `ENCRYPTION_KEY` environment variable to a base64-encoded
32-byte key, or instantiate `AES256Encryption(use_kms=True,
kms_key_id=<id>)` to fetch a data key from AWS KMS.

Output format: `ENC:{base64_encoded_iv_and_ciphertext}`

#### SHA-256 Hashing (`sha256_hash`)

One-way cryptographic hash. Salt comes from the `HASH_SALT` environment
variable (or the `salt` constructor argument).

Output format: `HASH:{hex_digest}`

#### Masking (`masking`)

Partial character replacement.

Options:

- `mask_char`: Character to use for masking (default: `*`)
- `visible_chars`: Number of characters preserved (default: `4`;
  `0` means full mask)
- `direction`: `right` (default), `left`, or `center` — which side of the
  string stays visible

Example: `john.smith@example.com` → `john****@example.com`

#### Tokenization (`tokenization`)

Replace each value with a generated surrogate token, stored in the
in-memory token vault for the lifetime of the Lambda invocation.

Options:

- `token_prefix`: Prefix on every token (default: `TOK_`)

Output format: `{token_prefix}{16-char alnum suffix}`

#### Redaction (`redact`)

Replace each value with a fixed redaction marker (default `[REDACTED]`).
Use this when the value should be neither reversible nor partially
visible.

### Rule Priorities

When multiple rules target the same `entity_type`, the lowest `priority`
value wins (`Policy.get_rule_for_entity` returns `min(matching, key=priority)`).
Use a small priority for the rule you want to dominate:

```yaml
rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: aes256_encrypt
    priority: 1

  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash
    priority: 5  # fallback if priority-1 rule is removed
```

If no rule matches an entity type, `settings.default_protection` is always
applied. Valid methods are `aes256_encrypt`, `sha256_hash`, `masking`,
`tokenization`, and `redact`.

## CloudFormation Parameters

The SAM template accepts these parameters:

| Parameter          | Description                                 | Default |
|--------------------|---------------------------------------------|---------|
| `Environment`      | Deployment environment (dev, staging, prod) | `dev`   |
| `LogRetentionDays` | CloudWatch log retention in days            | `30`    |

Bucket and table names are derived from `Environment` and the AWS account id
(`sdp-raw-data-${Environment}-${AccountId}`, `sdp-secure-data-${Environment}-${AccountId}`,
`sdp-audit-${Environment}`). Lambda memory (`3008` MB) and timeout (`300` s) are
fixed in `Globals.Function`. Audit-record TTL (90 days) is set in `lambda_handler.py`.

## File Format Configuration

### CSV Options

The CSV handler auto-detects the delimiter (comma, semicolon, tab, or pipe)
using `csv.Sniffer`. Encoding defaults to UTF-8 and is configurable via
`CSVHandler(encoding=...)`.

### JSON Options

Supported JSON structures:

- Array of objects: `[{...}, {...}]`
- Records wrapper: `{"records": [{...}]}`
- Nested objects: `{"data": {"customers": [...]}}`
- Newline-delimited JSON (NDJSON)

### Parquet Options

Parquet files are processed using PyArrow with automatic schema detection.

## Audit Configuration

### CloudWatch Logs

The Lambda function writes structured log entries to its own log group
(`/aws/lambda/sdp-data-protection-${Environment}`) for every record it
processes: ingest, pipeline duration, detection counts, protection counts,
and any errors. No custom CloudWatch metrics are emitted; the AWS/Lambda
namespace metrics (`Invocations`, `Errors`, `Duration`, `Throttles`,
`ConcurrentExecutions`) are charted on the dashboard the template provisions.

### DynamoDB Audit Table

The audit table uses a single-table design with a 90-day TTL on every item:

**Primary Key:**

- `pk`: Partition key — `FILE#${source_bucket}/${source_key}`
- `sk`: Sort key — `PROCESS#${iso8601_timestamp}`

**GSI1:**

- `gsi1pk`: Date partition — `DATE#${YYYY-MM-DD}`
- `gsi1sk`: File identifier — `FILE#${file_name}`

**Item attributes** (written by `lambda_handler._create_audit_record`):

- `request_id`, `source_bucket`, `source_key`, `secure_key`
- `file_format`, `success`, `duration_ms`, `timestamp`, `error`
- `detection_summary` — entity counts and columns with PII (raw entity texts
  are stripped before write to keep PII out of the audit log)
- `protection_summary` — total protections applied and method breakdown
- `stage_durations` — per-stage timings keyed by pipeline stage name
- `ttl` — Unix timestamp 90 days in the future

## Detection Threshold Tuning

Set `settings.confidence_threshold` in the policy YAML (default `0.7`):

| Threshold | Precision | Recall   | Use Case                                  |
|-----------|-----------|----------|-------------------------------------------|
| 0.3       | Lower     | Higher   | Maximum detection, accept false positives |
| 0.5       | Balanced  | Balanced | Aggressive detection                      |
| 0.7       | Higher    | Lower    | Minimise false positives (default)        |
| 0.9       | Highest   | Lowest   | Only high-confidence detections           |

## Performance Tuning

The SAM template provisions the Lambda with `MemorySize: 3008` (≈ 2 vCPU,
the default account quota — raise via AWS Service Quotas if higher is needed)
and `Timeout: 300` seconds, sized to load the `en_core_web_lg` spaCy model
on a cold start and process files up to roughly 1 MB inside the timeout.
Adjust both values in `infrastructure/template.yaml` (`Globals.Function`)
if your workload needs different limits.
