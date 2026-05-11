# Deployment Guide

This guide covers deploying the serverless data protection framework to AWS.

## Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed and configured
3. **AWS SAM CLI** installed
4. **Python 3.13**
5. **Docker** installed and running (the Lambda is packaged as a container image)

## AWS Permissions Required

The deployment user/role needs these permissions:

- CloudFormation full access
- S3 full access (or scoped to the SAM-managed deployment bucket)
- Lambda full access
- DynamoDB full access
- KMS full access
- CloudWatch Logs full access
- IAM role creation
- ECR access (SAM pushes the Lambda image to a managed ECR repo)

## Step-by-Step Deployment

### 1. Clone and Setup

```bash
git clone <repository-url>
cd serverless-data-protection

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt -r requirements-dev.txt
```

### 2. Configure AWS CLI

```bash
aws configure
aws sts get-caller-identity
```

### 3. Build the Application

```bash
cd infrastructure

sam build
sam validate
```

`sam build` reads `template.yaml`, builds the Lambda container image from the
project root using `Dockerfile`, and produces a deployment artefact under
`.aws-sam/build/`. The S3 buckets, DynamoDB table, KMS key, IAM role, and
CloudWatch dashboard are all created by the template — you do not need to
provision them yourself.

### 4. Deploy

**Option A: Guided deployment (first time)**

```bash
sam deploy --guided
```

Suggested prompt answers:

- Stack Name: `serverless-data-protection-dev`
- AWS Region: `us-east-1` (or your preferred region)
- Parameter `Environment`: `dev`
- Parameter `LogRetentionDays`: `30`
- Confirm changes before deploy: `Y`
- Allow SAM CLI IAM role creation: `Y`
- Disable rollback: `N`
- Save arguments to configuration file: `Y` (writes `samconfig.toml`)

**Option B: Non-interactive deployment**

```bash
sam deploy \
  --stack-name serverless-data-protection-dev \
  --capabilities CAPABILITY_NAMED_IAM \
  --resolve-image-repos \
  --parameter-overrides \
    Environment=dev \
    LogRetentionDays=30
```

The first deployment also creates an ECR repo for the Lambda image; subsequent
deployments reuse it.

### 5. Verify Deployment

```bash
aws cloudformation describe-stacks \
  --stack-name serverless-data-protection-dev \
  --query 'Stacks[0].StackStatus'

aws lambda get-function \
  --function-name sdp-data-protection-dev \
  --query 'Configuration.[State,LastUpdateStatus]'

aws dynamodb describe-table \
  --table-name sdp-audit-dev \
  --query 'Table.TableStatus'

aws s3 ls | grep sdp-
```

The stack outputs (`RawDataBucketName`, `SecureDataBucketName`,
`AuditTableName`, `EncryptionKeyArn`, `DataProtectionFunctionArn`,
`DashboardUrl`) are also available via `aws cloudformation describe-stacks`.

## Testing the Deployment

### Upload a Test File

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
RAW_BUCKET="sdp-raw-data-dev-${ACCOUNT_ID}"

cat > test.csv << 'EOF'
id,name,email,phone
1,John Smith,john@example.com,+44 7911 123456
2,Jane Doe,jane@company.co.uk,020 7946 0958
EOF

aws s3 cp test.csv "s3://${RAW_BUCKET}/incoming/test.csv"
```

### Check Processing Results

```bash
SECURE_BUCKET="sdp-secure-data-dev-${ACCOUNT_ID}"

aws s3 ls "s3://${SECURE_BUCKET}/protected/incoming/"

aws logs tail /aws/lambda/sdp-data-protection-dev --follow
```

### Query Audit Records

```bash
aws dynamodb query \
  --table-name sdp-audit-dev \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values \
    "{\":pk\": {\"S\": \"FILE#${RAW_BUCKET}/incoming/test.csv\"}}"
```

## Environment-Specific Deployments

```bash
# Staging
sam deploy --stack-name serverless-data-protection-staging \
  --parameter-overrides Environment=staging LogRetentionDays=60

# Production
sam deploy --stack-name serverless-data-protection-prod \
  --parameter-overrides Environment=prod LogRetentionDays=90
```

## Updating the Deployment

```bash
sam build
sam deploy
```

When changing the policy YAML in `policies/`, redeploy — the policy is
baked into the Lambda image at build time.

## Cleanup

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws s3 rm "s3://sdp-raw-data-dev-${ACCOUNT_ID}" --recursive
aws s3 rm "s3://sdp-secure-data-dev-${ACCOUNT_ID}" --recursive

sam delete --stack-name serverless-data-protection-dev
```

`sam delete` removes the CloudFormation stack and prompts for confirmation
before deleting the SAM-managed deployment bucket and ECR repo.

## Troubleshooting

### Lambda Timeout

If processing exceeds the 300-second timeout, increase `Timeout` in
`infrastructure/template.yaml` under `Globals.Function`, or split very
large input files before upload.

### Permission Errors

If the Lambda cannot access S3, DynamoDB, or KMS:

1. Confirm the stack created `LambdaExecutionRole` and that the IAM policies
   in `template.yaml` reference the correct resource ARNs.
2. Check the Lambda's environment variables (`RAW_BUCKET_NAME`,
   `SECURE_BUCKET_NAME`, `AUDIT_TABLE_NAME`, `KMS_KEY_ID`) match the stack
   resources.

### Detection Issues

If PII is not being detected:

1. Lower `settings.confidence_threshold` in `policies/protection_policy.yaml`
   and redeploy.
2. Verify the file extension is `.csv`, `.json`, `.ndjson`, or `.parquet` —
   other suffixes are filtered out by the EventBridge rule.
3. Inspect `/aws/lambda/sdp-data-protection-dev` logs in CloudWatch.

### Memory Errors

If the Lambda runs out of memory, increase `MemorySize` in
`Globals.Function` (the template ships with `3008` MB) and redeploy.

## Monitoring

### CloudWatch Dashboard

The template provisions a dashboard named `sdp-monitoring-${Environment}`
charting Lambda `Invocations`, `Errors`, `Duration`, and
`ConcurrentExecutions`. The full URL is exported as the `DashboardUrl`
stack output.

### Alarms

The template creates four alarms keyed off AWS/Lambda metrics: error rate
(>5 errors per 5 min), duration (>120 s average per 5 min), throttles
(any), and high invocation count (>1000 per hour). Tune the thresholds in
`template.yaml` if your workload differs.

## Security Considerations

1. **Encryption at Rest**: S3 buckets and DynamoDB use AES-256 SSE
   (configured by the template).
2. **Encryption in Transit**: All AWS service calls use HTTPS endpoints.
3. **KMS Key Rotation**: The framework's KMS key has automatic rotation
   enabled.
4. **VPC**: Consider deploying the Lambda inside a VPC for network
   isolation if your data is sensitive.
5. **Least Privilege**: Review the IAM policies in `LambdaExecutionRole`
   before promoting to production.
6. **Audit Logs**: Enable CloudTrail for cross-service API auditing in
   addition to the per-file DynamoDB audit table.
