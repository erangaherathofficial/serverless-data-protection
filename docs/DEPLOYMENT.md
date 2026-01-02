# Deployment Guide

This guide covers deploying the serverless data protection framework to AWS.

## Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed and configured
3. **AWS SAM CLI** installed
4. **Python 3.11+** installed
5. **Docker** (optional, for local testing)

## AWS Permissions Required

The deployment user/role needs these permissions:
- CloudFormation full access
- S3 full access (or scoped to deployment bucket)
- Lambda full access
- DynamoDB full access
- KMS full access
- CloudWatch Logs full access
- IAM role creation

## Step-by-Step Deployment

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd serverless-data-protection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure AWS CLI

```bash
# Configure credentials
aws configure

# Verify configuration
aws sts get-caller-identity
```

### 3. Create S3 Buckets

```bash
# Create deployment artifact bucket
aws s3 mb s3://your-deployment-bucket-name

# Create source data bucket
aws s3 mb s3://your-source-data-bucket

# Create secure output bucket
aws s3 mb s3://your-secure-output-bucket

# Create policy bucket
aws s3 mb s3://your-policy-bucket
```

### 4. Upload Policy File

```bash
# Upload protection policy
aws s3 cp policies/protection_policy.yaml s3://your-policy-bucket/policies/
```

### 5. Build the Application

```bash
cd infrastructure

# Build with SAM
sam build

# Validate template
sam validate
```

### 6. Deploy

**Option A: Guided deployment (first time)**

```bash
sam deploy --guided
```

Follow the prompts:
- Stack Name: `data-protection-stack`
- AWS Region: `eu-west-2` (or your preferred region)
- SourceBucketName: `your-source-data-bucket`
- SecureBucketName: `your-secure-output-bucket`
- PolicyBucketName: `your-policy-bucket`
- Environment: `dev`
- Confirm changes: `Y`
- Allow SAM CLI IAM role creation: `Y`

**Option B: Non-interactive deployment**

```bash
sam deploy \
  --stack-name data-protection-stack \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    SourceBucketName=your-source-data-bucket \
    SecureBucketName=your-secure-output-bucket \
    PolicyBucketName=your-policy-bucket \
    Environment=dev
```

### 7. Verify Deployment

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name data-protection-stack \
  --query 'Stacks[0].StackStatus'

# List Lambda functions
aws lambda list-functions \
  --query 'Functions[?starts_with(FunctionName, `DataProtection`)]'

# Check DynamoDB table
aws dynamodb describe-table \
  --table-name DataProtection-Audit-dev
```

## Testing the Deployment

### Upload Test File

```bash
# Create a test CSV file
cat > test.csv << 'EOF'
id,name,email,phone
1,John Smith,john@example.com,+44 7911 123456
2,Jane Doe,jane@company.co.uk,020 7946 0958
EOF

# Upload to source bucket
aws s3 cp test.csv s3://your-source-data-bucket/incoming/
```

### Check Processing Results

```bash
# Wait a few seconds for processing

# Check secure bucket for output
aws s3 ls s3://your-secure-output-bucket/protected/

# View Lambda logs
aws logs tail /aws/lambda/DataProtection-DataProtectionFunction-dev \
  --follow
```

### Query Audit Records

```bash
# Query DynamoDB for processing records
aws dynamodb query \
  --table-name DataProtection-Audit-dev \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk": {"S": "FILE#your-source-data-bucket/incoming/test.csv"}}'
```

## Environment-Specific Deployments

### Development

```bash
sam deploy \
  --stack-name data-protection-dev \
  --parameter-overrides Environment=dev LambdaMemorySize=512
```

### Staging

```bash
sam deploy \
  --stack-name data-protection-staging \
  --parameter-overrides Environment=staging LambdaMemorySize=1024
```

### Production

```bash
sam deploy \
  --stack-name data-protection-prod \
  --parameter-overrides \
    Environment=prod \
    LambdaMemorySize=2048 \
    LambdaTimeout=300
```

## Updating the Deployment

```bash
# Make code changes, then:
sam build
sam deploy
```

## Rolling Back

```bash
# Rollback to previous version
aws cloudformation rollback-stack \
  --stack-name data-protection-stack
```

## Cleanup

```bash
# Empty S3 buckets first
aws s3 rm s3://your-source-data-bucket --recursive
aws s3 rm s3://your-secure-output-bucket --recursive

# Delete the stack
aws cloudformation delete-stack \
  --stack-name data-protection-stack

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name data-protection-stack
```

## Troubleshooting

### Lambda Timeout

If processing times out:
1. Increase `LambdaTimeout` parameter
2. Increase `LambdaMemorySize` for more CPU
3. Check file size limits in policy

### Permission Errors

If Lambda can't access S3/DynamoDB:
1. Check IAM role has required permissions
2. Verify bucket names in environment variables
3. Check KMS key permissions for encryption

### Detection Issues

If PII not detected:
1. Check `DETECTION_THRESHOLD` setting
2. Verify file format is supported
3. Review CloudWatch logs for errors

### Memory Errors

If Lambda runs out of memory:
1. Increase `LambdaMemorySize`
2. Process smaller files
3. Enable chunked processing (future feature)

## Monitoring

### CloudWatch Dashboard

The deployment creates a CloudWatch dashboard at:
`https://console.aws.amazon.com/cloudwatch/home?region=YOUR_REGION#dashboards:name=DataProtection-Dashboard`

### Alarms

Set up alarms for:
- Error rate > 5%
- Processing duration > 60 seconds
- Memory utilization > 80%

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name DataProtection-Errors \
  --metric-name ProcessingErrors \
  --namespace DataProtection \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1
```

## Security Considerations

1. **Encryption at Rest**: Enable S3 bucket encryption
2. **Encryption in Transit**: Use HTTPS endpoints only
3. **KMS Key Rotation**: Enable automatic key rotation
4. **VPC**: Consider deploying Lambda in VPC for network isolation
5. **Least Privilege**: Review and minimize IAM permissions
6. **Audit Logs**: Enable CloudTrail for API auditing
