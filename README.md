# Serverless Data Protection Framework

Automated and Policy-Driven Data Protection for Cloud Data Lakes.

## Overview

A serverless framework using AWS Lambda, S3, and Microsoft Presidio for automated PII detection and protection across
Parquet, CSV, and JSON file formats. The system processes files uploaded to S3, detects personally identifiable
information using NLP-based analysis, applies configurable protection methods, and maintains a comprehensive audit
trail.

## Key Features

- **Multi-format Support**: CSV, JSON (including NDJSON), and Parquet
- **PII Detection**: Microsoft Presidio with 18 entity types including UK-specific patterns
- **Flexible Protection**: AES-256 encryption, SHA-256 hashing, masking, tokenization, redaction
- **Policy-Driven**: YAML-based configuration for protection rules
- **Schema Preservation**: Validates output matches input schema
- **Audit Trail**: CloudWatch logs and DynamoDB records
- **Serverless**: Event-driven Lambda architecture

## Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │              Four-Layer Architecture                     │
┌───────────────────┼───────────────────┬───────────────────┬─────────────────┤
│    Ingestion      │    Detection      │     Policy        │    Security     │
├───────────────────┼───────────────────┼───────────────────┼─────────────────┤
│  S3 Triggers      │  Presidio PII     │  YAML Parser      │  AES-256        │
│  Lambda Handler   │  Custom UK        │  Rule Evaluator   │  SHA-256        │
│  File Handlers    │  Recognizers      │  Priority Rules   │  Masking        │
│  Format Validate  │  NLP Analysis     │  Default Fallback │  Tokenization   │
└───────────────────┴───────────────────┴───────────────────┴─────────────────┘
```

## Processing Pipeline

```
┌─────────┐   ┌──────────┐   ┌────────┐   ┌──────────┐   ┌─────────┐   ┌────────┐   ┌────────┐
│ RECEIVE │ → │ VALIDATE │ → │ DETECT │ → │ EVALUATE │ → │ PROTECT │ → │ SCHEMA │ → │ OUTPUT │
└─────────┘   └──────────┘   └────────┘   └──────────┘   └─────────┘   └────────┘   └────────┘
     │             │             │             │              │            │            │
   S3 Event    Format OK?    Presidio     Match Rules    Apply        Validate     Write to
   Trigger     Parse File    Scan PII     Get Actions    Methods      Schema       Secure S3
```

## Project Structure

```
serverless-data-protection/
├── src/
│   ├── lambda_handler.py          # Lambda entry point
│   ├── aws/                        # AWS client management
│   │   └── client_manager.py       # Singleton pattern
│   ├── handlers/                   # File format handlers
│   │   ├── base_handler.py         # Abstract base (Template Method)
│   │   ├── csv_handler.py          # CSV processing
│   │   ├── json_handler.py         # JSON/NDJSON processing
│   │   ├── parquet_handler.py      # Parquet processing
│   │   └── handler_factory.py      # Factory pattern
│   ├── detection/                  # PII detection
│   │   ├── presidio_detector.py    # Presidio integration
│   │   └── custom_recognizers.py   # UK-specific patterns
│   ├── policy/                     # Policy engine
│   │   ├── policy_parser.py        # YAML parsing
│   │   └── rule_evaluator.py       # Rule matching
│   ├── protection/                 # Protection strategies
│   │   ├── base_protection.py      # Strategy pattern
│   │   ├── aes256_encryption.py    # AES-256-CBC
│   │   ├── sha256_hashing.py       # SHA-256
│   │   ├── masking.py              # Masking strategies
│   │   └── tokenization.py         # Token generation
│   ├── validation/                 # Schema validation
│   │   └── schema_validator.py     # Schema preservation
│   └── pipeline/                   # Pipeline orchestration
│       └── pipeline_orchestrator.py # 7-stage pipeline
├── ui/                             # Streamlit demo UI
│   ├── __init__.py                 # Package marker
│   ├── app.py                      # Streamlit entry point
│   ├── aws_client.py               # AWS access for the UI
│   └── components.py               # Render helpers
├── policies/                       # YAML policies
│   └── protection_policy.yaml
├── infrastructure/                 # CloudFormation/SAM
│   └── template.yaml
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   ├── security/                   # Security tests
│   └── performance/                # Performance tests
├── test_data/                      # Synthetic test data generator
│   └── generate_test_data.py
├── scripts/                        # Utility scripts
│   └── run_tests.py
├── docs/                           # Documentation
│   ├── CONFIGURATION.md
│   └── DEPLOYMENT.md
├── requirements.txt
├── requirements-dev.txt
└── requirements-ui.txt
```

## Quick Start

### Prerequisites

- Python 3.13
- AWS Account with CLI configured
- AWS SAM CLI

### Installation

```bash
# Clone repository
git clone <repository-url>
cd serverless-data-protection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt
```

### Local Testing

```bash
# Run unit tests
python scripts/run_tests.py unit

# Run all tests
python scripts/run_tests.py all

# Run with coverage
python scripts/run_tests.py coverage
```

### Deployment

```bash
cd infrastructure
sam build
sam deploy --guided
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed instructions.

## Local Demo

A Streamlit UI is available for end-to-end demos against a deployed stack.

```bash
export AWS_REGION=us-east-1
export RAW_BUCKET_NAME=sdp-raw-data-dev-<account-id>
export SECURE_BUCKET_NAME=sdp-secure-data-dev-<account-id>
export AUDIT_TABLE_NAME=sdp-audit-dev

pip install -r requirements.txt -r requirements-ui.txt
streamlit run ui/app.py
```

AWS credentials must be configured via the standard boto3 credential chain.

## Configuration

Protection policies are defined in YAML:

```yaml
version: "1.0"
settings:
  confidence_threshold: 0.7
  default_protection: masking

rules:
  - entity_type: EMAIL_ADDRESS
    protection_method: sha256_hash

  - entity_type: CREDIT_CARD
    protection_method: aes256_encrypt

  - entity_type: PHONE_NUMBER
    protection_method: masking
    options:
      visible_chars: 4
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for full options.

## Supported PII Types

### Standard Entities

| Entity          | Description          |
|-----------------|----------------------|
| `EMAIL_ADDRESS` | Email addresses      |
| `PHONE_NUMBER`  | Phone numbers        |
| `CREDIT_CARD`   | Credit card numbers  |
| `PERSON`        | Person names         |
| `LOCATION`      | Addresses, places    |
| `DATE_TIME`     | Dates and times      |
| `IP_ADDRESS`    | IP addresses         |
| `IBAN_CODE`     | Bank account numbers |

### UK-Specific Entities

| Entity               | Description                  |
|----------------------|------------------------------|
| `UK_NHS`             | NHS numbers                  |
| `UK_NINO`            | National Insurance numbers   |
| `UK_POSTCODE`        | UK postal codes              |
| `UK_PHONE`           | UK phone formats             |
| `UK_NAME`            | Common UK first/last names   |
| `UK_CITY`            | Major UK cities and towns    |
| `UK_DRIVERS_LICENSE` | Driving licence numbers      |
| `UK_PASSPORT`        | UK passport numbers          |
| `UK_BANK_ACCOUNT`    | UK bank accounts             |
| `UK_VRN`             | Vehicle registration numbers |

## Protection Methods

| Method           | Type       | Description                             |
|------------------|------------|-----------------------------------------|
| `aes256_encrypt` | Reversible | AES-256-CBC encryption (optional KMS)   |
| `sha256_hash`    | One-way    | SHA-256 cryptographic hash              |
| `masking`        | One-way    | Partial character masking               |
| `tokenization`   | Reversible | Surrogate value replacement             |
| `redact`         | One-way    | Replaces value with `[REDACTED]` marker |

## Design Patterns

- **Singleton**: AWS client management
- **Factory**: File handler selection
- **Strategy**: Protection technique selection
- **Template Method**: Base handler structure
- **Pipeline**: Data transformation stages

## Quick Example

```python
from src.pipeline.pipeline_orchestrator import create_pipeline

# Create pipeline
pipeline = create_pipeline()

# Process file
result = pipeline.process(
    content=file_bytes,
    file_name="data.csv"
)

if result.success:
    protected_data = result.protected_data
    print(f"Detected: {len(result.detection_summary['entities'])} entities")
    print(f"Protected: {result.protection_summary['protections_applied']} values")
```

## Testing

```bash
# Unit tests
python scripts/run_tests.py unit

# Integration tests
python scripts/run_tests.py integration

# Security tests (PII accuracy)
python scripts/run_tests.py security

# Performance tests
python scripts/run_tests.py performance

# All tests with coverage
python scripts/run_tests.py coverage
```

## Performance

The deployed Lambda is provisioned at `MemorySize: 3008` MB and `Timeout:
300` s. Cold-start dominates the first invocation (~60–70 s, almost entirely
the spaCy `en_core_web_lg` model load); warm invocations process files up
to roughly 1 MB in 3–10 s. The `LatencyAlarm` fires when the rolling
5-minute average duration exceeds 120 s.

## Security Considerations

- AWS KMS key provisioned with rotation enabled (opt-in for AES envelope encryption)
- No PII stored in logs (only metadata)
- DynamoDB audit records with TTL; raw entity texts stripped before write
- S3 bucket encryption enabled
- IAM policies scoped to specific stack resources

## License

This project is part of an MSc dissertation at the University of Westminster, in collaboration with the Informatics
Institute of Technology.

## Acknowledgements

- [Microsoft Presidio](https://microsoft.github.io/presidio/) for PII detection
- [AWS SAM](https://aws.amazon.com/serverless/sam/) for serverless deployment
- [PyArrow](https://arrow.apache.org/docs/python/) for Parquet support
