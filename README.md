# Serverless Data Protection Framework

Automated and Policy-Driven Data Protection for Cloud Data Lakes.

## Overview

A serverless framework using AWS Lambda, S3, and Microsoft Presidio for automated PII detection and protection across
Parquet, CSV, and JSON file formats. The system processes files uploaded to S3, detects personally identifiable
information using NLP-based analysis, applies configurable protection methods, and maintains a comprehensive audit
trail.

## Key Features

- **Multi-format Support**: CSV, JSON (including NDJSON), and Parquet
- **PII Detection**: Microsoft Presidio with 15+ entity types including UK-specific patterns
- **Flexible Protection**: AES-256 encryption, SHA-256 hashing, masking, tokenization
- **Policy-Driven**: YAML-based configuration for protection rules
- **Schema Preservation**: Validates output matches input schema
- **Audit Trail**: CloudWatch metrics and DynamoDB records
- **Serverless**: Event-driven Lambda architecture

## Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │              Four-Layer Architecture                     │
┌───────────────────┼───────────────────┬───────────────────┬─────────────────┤
│    Ingestion      │    Detection      │     Policy        │    Security     │
├───────────────────┼───────────────────┼───────────────────┼─────────────────┤
│  S3 Triggers      │  Presidio PII     │  YAML Engine      │  AES-256        │
│  Lambda Handler   │  Custom UK        │  Rule Evaluation  │  SHA-256        │
│  File Handlers    │  Recognizers      │  Protection Map   │  Masking        │
│  Format Validate  │  NLP Analysis     │  Priority Rules   │  Tokenization   │
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
│   │   ├── rule_evaluator.py       # Rule matching
│   │   └── protection_mapper.py    # Protection planning
│   ├── protection/                 # Protection strategies
│   │   ├── base_protection.py      # Strategy pattern
│   │   ├── aes256_encryption.py    # AES-256-CBC
│   │   ├── sha256_hashing.py       # SHA-256/512
│   │   ├── masking.py              # Masking strategies
│   │   └── tokenization.py         # Token generation
│   ├── validation/                 # Schema validation
│   │   └── schema_validator.py     # Schema preservation
│   ├── pipeline/                   # Pipeline orchestration
│   │   └── pipeline_orchestrator.py # 7-stage pipeline
│   └── audit/                      # Audit trail
│       ├── cloudwatch_logger.py    # Metrics and logs
│       └── dynamodb_writer.py      # Audit records
├── policies/                       # YAML policies
│   └── protection_policy.yaml
├── infrastructure/                 # CloudFormation/SAM
│   └── template.yaml
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   ├── security/                   # Security tests
│   ├── performance/                # Performance tests
│   └── test_data/                  # Test data generator
├── scripts/                        # Utility scripts
│   └── run_tests.py
├── docs/                           # Documentation
│   ├── API.md
│   ├── CONFIGURATION.md
│   └── DEPLOYMENT.md
└── requirements.txt
```

## Quick Start

### Prerequisites

- Python 3.11+
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
pip install -r requirements.txt
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

## Configuration

Protection policies are defined in YAML:

```yaml
version: "1.0"
settings:
  detection_threshold: 0.5
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
| `UK_DRIVERS_LICENSE` | Driving licence numbers      |
| `UK_PASSPORT`        | UK passport numbers          |
| `UK_BANK_ACCOUNT`    | UK bank accounts             |
| `UK_VRN`             | Vehicle registration numbers |

## Protection Methods

| Method           | Type       | Description                     |
|------------------|------------|---------------------------------|
| `aes256_encrypt` | Reversible | AES-256-CBC encryption with KMS |
| `sha256_hash`    | One-way    | SHA-256 cryptographic hash      |
| `masking`        | One-way    | Partial character masking       |
| `tokenization`   | Reversible | Surrogate value replacement     |

## Design Patterns

- **Singleton**: AWS client management
- **Factory**: File handler selection
- **Strategy**: Protection technique selection
- **Template Method**: Base handler structure
- **Pipeline**: Data transformation stages

## API Reference

See [docs/API.md](docs/API.md) for detailed API documentation.

### Quick Example

```python
from src.pipeline.pipeline_orchestrator import create_pipeline

# Create pipeline
pipeline = create_pipeline()

# Process file
result = pipeline.process(
    data=file_bytes,
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

Tested performance targets:

- 1KB file: <5 seconds
- 10KB file: <10 seconds
- 100KB file: <30 seconds
- 1MB file: <60 seconds

## Security Considerations

- Encryption keys managed by AWS KMS
- No PII stored in logs (only metadata)
- DynamoDB audit records with TTL
- S3 bucket encryption enabled
- IAM least privilege access

## License

This project is part of an MSc dissertation at the University of Plymouth.

## Acknowledgements

- [Microsoft Presidio](https://microsoft.github.io/presidio/) for PII detection
- [AWS SAM](https://aws.amazon.com/serverless/sam/) for serverless deployment
- [PyArrow](https://arrow.apache.org/docs/python/) for Parquet support
