# bptools

`bptools` is a Go-based AWS best-practice check runner.
It collects AWS resource data and executes a large set of service-specific rules.

## Download

**One-liner install (Linux & macOS)** — detects your OS and CPU architecture automatically:

```bash
curl -fsSL https://awsutils.github.io/bptools/install.sh | sh
```

To install to a custom directory:

```bash
INSTALL_DIR=~/.local/bin curl -fsSL https://awsutils.github.io/bptools/install.sh | sh
```

Or download a binary directly from [awsutils.github.io/bptools](https://awsutils.github.io/bptools) or the [Releases](https://github.com/awsutils/bptools/releases/latest) page.

**Linux (amd64)**
```bash
curl -Lo bptools https://awsutils.github.io/bptools/bptools-linux-amd64
chmod +x bptools
```

**Linux (arm64)**
```bash
curl -Lo bptools https://awsutils.github.io/bptools/bptools-linux-arm64
chmod +x bptools
```

**macOS (Apple Silicon)**
```bash
curl -Lo bptools https://awsutils.github.io/bptools/bptools-darwin-arm64
chmod +x bptools
```

**macOS (Intel)**
```bash
curl -Lo bptools https://awsutils.github.io/bptools/bptools-darwin-amd64
chmod +x bptools
```

**Windows (amd64)**

Download [`bptools-windows-amd64.exe`](https://awsutils.github.io/bptools/bptools-windows-amd64.exe).

Verify the download against [`checksums.txt`](https://awsutils.github.io/bptools/checksums.txt).

## Docker

Images are published to the GitHub Container Registry on every release for `linux/amd64` and `linux/arm64`.

**Pull the latest image:**

```bash
docker pull ghcr.io/awsutils/bptools:latest
```

**Run with environment-variable credentials:**

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION \
  ghcr.io/awsutils/bptools:latest
```

**Run with a mounted AWS credentials file:**

```bash
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -e AWS_PROFILE=myprofile \
  -e AWS_REGION=us-east-1 \
  ghcr.io/awsutils/bptools:latest
```

**Pass CLI flags:**

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
  ghcr.io/awsutils/bptools:latest -services ec2,s3,iam
```

**Pin to a specific release:**

```bash
docker run --rm ... ghcr.io/awsutils/bptools:v2026.02.13.1
```

## Requirements

- Go `1.25+`
- AWS credentials and region configured (for example via environment variables, shared config, or IAM role)
- Permission to read the AWS APIs used by the checks you run

## Build

```bash
CGO_ENABLED=false go build .
```

## Run

```bash
./bptools
```

### CLI flags

- `-concurrency` (default: `20`): maximum concurrent checks
- `-ids`: comma-separated check IDs to run
- `-services`: comma-separated service names to run
- `-prefetch` (default: `true`): prefetch AWS caches before check execution

### Examples

Run only specific checks:

```bash
./bptools -ids access-keys-rotated,ec2-imdsv2-check
```

Run only specific services:

```bash
./bptools -services ec2,s3,iam
```

Run with lower concurrency:

```bash
./bptools -concurrency 8
```

## Important behavior

The current CLI intentionally does **not** emit results to stdout/stderr.  
Checks execute, but result output is currently disabled in `main.go`.

## EC2 rule configuration (allowlist-driven checks)

These environment variables drive EC2 checks that require policy input:

- `BPTOOLS_APPROVED_AMI_IDS`  
  Comma-separated AMI IDs for:
  - `approved-amis-by-id`
  - `ec2-instance-launched-with-allowed-ami`

- `BPTOOLS_APPROVED_AMI_TAGS`  
  Comma-separated AMI tag filters in `key=value` or `key` form for:
  - `approved-amis-by-tag`
  - `ec2-instance-launched-with-allowed-ami`

- `BPTOOLS_ALLOWED_INSTANCE_TENANCIES`  
  Comma-separated allowed tenancies for:
  - `desired-instance-tenancy`

- `BPTOOLS_ALLOWED_INSTANCE_TYPES`  
  Comma-separated allowed instance types for:
  - `desired-instance-type`

Example:

```bash
export BPTOOLS_APPROVED_AMI_IDS=ami-0123456789abcdef0,ami-0fedcba9876543210
export BPTOOLS_APPROVED_AMI_TAGS=Approved=true,SecurityBaseline
export BPTOOLS_ALLOWED_INSTANCE_TENANCIES=default,dedicated
export BPTOOLS_ALLOWED_INSTANCE_TYPES=t3.micro,t3.small,m6i.large
```

## Built-in defaults for env-driven checks

When these environment variables are not set, `bptools` now uses these defaults:

- `BPTOOLS_DYNAMODB_MAX_THROUGHPUT_USAGE_PERCENT=80`
- `BPTOOLS_DYNAMODB_READ_CAPACITY_LIMIT` / `BPTOOLS_DYNAMODB_WRITE_CAPACITY_LIMIT`:
  auto-resolved from DynamoDB `DescribeLimits` when possible, otherwise fallback to `40000`
- `BPTOOLS_AUTHORIZED_PUBLIC_PORTS=80,443`
- `BPTOOLS_RESTRICTED_COMMON_PORTS=20,21,3306,3389,4333`
- `BPTOOLS_REQUIRED_VPC_ENDPOINT_SERVICE=s3`
- `BPTOOLS_CW_ALARM_RESOURCE_METRIC_NAME=CPUUtilization`
- `BPTOOLS_CW_ALARM_RESOURCE_NAMESPACE=AWS/EC2`
- `BPTOOLS_CW_ALARM_RESOURCE_DIMENSION=InstanceId`
- `BPTOOLS_CW_ALARM_SETTINGS_METRIC_NAME=CPUUtilization`
- `BPTOOLS_CW_ALARM_SETTINGS_NAMESPACE=AWS/EC2`
- `BPTOOLS_CW_ALARM_SETTINGS_EVALUATION_PERIODS_MIN=2`
- `BPTOOLS_CW_ALARM_SETTINGS_PERIOD_SECONDS_MAX=300`
- `BPTOOLS_CW_ALARM_SETTINGS_COMPARISON_OPERATORS=GreaterThanOrEqualToThreshold,GreaterThanThreshold,LessThanThreshold,LessThanOrEqualToThreshold`
- `BPTOOLS_LAMBDA_MAX_TIMEOUT_SECONDS=900`
- `BPTOOLS_LAMBDA_MIN_MEMORY_MB=128`
- `BPTOOLS_LAMBDA_MAX_MEMORY_MB=10240`
- `BPTOOLS_ALLOWED_INSTANCE_TENANCIES=default,dedicated,host`
- `BPTOOLS_IGNORE_DELETED_RESOURCES=true` (ignore resources whose IDs indicate deleted/deleting/terminated states)
- `BPTOOLS_IGNORE_DEFAULT_RESOURCES_IN_TAG_CHECKS=true` (ignore AWS default resources for tagging checks)
- `BPTOOLS_IGNORE_AWS_MANAGED_KMS_KEYS=true` (ignore AWS-managed KMS keys for `kms-key-tagged`)

Unset policy/allowlist envs now default to permissive/not-applicable behavior:

- `BPTOOLS_APPROVED_AMI_IDS`, `BPTOOLS_APPROVED_AMI_TAGS`
- `BPTOOLS_ALLOWED_INSTANCE_TYPES`
- `BPTOOLS_MANAGEDINSTANCE_REQUIRED_APPLICATIONS`
- `BPTOOLS_MANAGEDINSTANCE_BLACKLISTED_APPLICATIONS`
- `BPTOOLS_MANAGEDINSTANCE_BLACKLISTED_INVENTORY_TYPES`
- `BPTOOLS_REQUIRED_POLICY_ARNS`, `BPTOOLS_REQUIRED_POLICY_NAMES`
- `BPTOOLS_REQUIRED_ROLE_MANAGED_POLICY_ARNS`
- `BPTOOLS_SAGEMAKER_NOTEBOOK_SUPPORTED_PLATFORM_VERSIONS`
- `BPTOOLS_S3_CONTROL_POLICY_JSON`
- `BPTOOLS_AUTHORIZED_IGW_VPC_IDS`

## Development

- Format: `gofmt -w .`
- Build check: `CGO_ENABLED=false go build .`

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications).

## License

This project is licensed under MIT-0. See [LICENSE](LICENSE).
