# bptools

`bptools` is a Go-based AWS best-practice check runner.  
It collects AWS resource data and executes a large set of service-specific rules.

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

## Development

- Format: `gofmt -w .`
- Build check: `CGO_ENABLED=false go build .`

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications).

## License

This project is licensed under MIT-0. See [LICENSE](LICENSE).
