package checks

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func RegisterDynamoDBChecks(d *awsdata.Data) {
	// dynamodb-autoscaling-enabled
	checker.Register(EnabledCheck(
		"dynamodb-autoscaling-enabled",
		"Checks if Amazon DynamoDB tables or global secondary indexes can process read/write capacity using on-demand mode or provisioned mode with auto scaling enabled. The rule is NON_COMPLIANT if either mode is used without auto scaling enabled",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			auto, err := d.DynamoDBAutoScaling.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, enabled := range auto {
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// dynamodb-pitr-enabled
	checker.Register(EnabledCheck(
		"dynamodb-pitr-enabled",
		"Checks if point-in-time recovery (PITR) is enabled for Amazon DynamoDB tables. The rule is NON_COMPLIANT if PITR is not enabled for DynamoDB tables.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			pitr, err := d.DynamoDBPITR.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, enabled := range pitr {
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// dynamodb-table-deletion-protection-enabled
	checker.Register(EnabledCheck(
		"dynamodb-table-deletion-protection-enabled",
		"Checks if an Amazon DynamoDB table have deletion protection set to enabled. The rule is NON_COMPLIANT if the table have deletion protection set to disabled.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, t := range tables {
				enabled := t.DeletionProtectionEnabled != nil && *t.DeletionProtectionEnabled
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// dynamodb-table-encryption-enabled + dynamodb-table-encrypted-kms
	checker.Register(EncryptionCheck(
		"dynamodb-table-encryption-enabled",
		"Checks if the Amazon DynamoDB tables are encrypted and checks their status. The rule is COMPLIANT if the status is enabled or enabling.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, t := range tables {
				encrypted := t.SSEDescription != nil &&
					(t.SSEDescription.Status == dynamodbtypes.SSEStatusEnabled || t.SSEDescription.Status == dynamodbtypes.SSEStatusEnabling)
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"dynamodb-table-encrypted-kms",
		"Checks if Amazon DynamoDB table is encrypted with AWS Key Management Service (KMS). The rule is NON_COMPLIANT if Amazon DynamoDB table is not encrypted with AWS KMS. The rule is also NON_COMPLIANT if the encrypted AWS KMS key is not present in kmsKeyArns input parameter.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, t := range tables {
				encrypted := t.SSEDescription != nil && t.SSEDescription.SSEType == dynamodbtypes.SSETypeKms
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// dynamodb-throughput-limit-check
	checker.Register(ConfigCheck(
		"dynamodb-throughput-limit-check",
		"Checks if provisioned DynamoDB throughput is approaching the maximum limit for your account. By default, the rule checks if provisioned throughput exceeds a threshold of 80 percent of your account limits.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			readLimit := dynamodbInt64Env("BPTOOLS_DYNAMODB_READ_CAPACITY_LIMIT", 0)
			writeLimit := dynamodbInt64Env("BPTOOLS_DYNAMODB_WRITE_CAPACITY_LIMIT", 0)
			maxUsagePercent := dynamodbInt64Env("BPTOOLS_DYNAMODB_MAX_THROUGHPUT_USAGE_PERCENT", 80)
			limitSource := "env"
			if readLimit <= 0 || writeLimit <= 0 {
				limitSource = "aws-describe-limits"
				limitsOutput, limitsErr := d.Clients.DynamoDB.DescribeLimits(context.Background(), &dynamodb.DescribeLimitsInput{})
				if limitsErr != nil {
					limitSource = "static-default"
					if readLimit <= 0 {
						readLimit = 40000
					}
					if writeLimit <= 0 {
						writeLimit = 40000
					}
				} else {
					if readLimit <= 0 && limitsOutput.AccountMaxReadCapacityUnits != nil {
						readLimit = *limitsOutput.AccountMaxReadCapacityUnits
					}
					if writeLimit <= 0 && limitsOutput.AccountMaxWriteCapacityUnits != nil {
						writeLimit = *limitsOutput.AccountMaxWriteCapacityUnits
					}
					if readLimit <= 0 {
						readLimit = 40000
						limitSource = "mixed-default"
					}
					if writeLimit <= 0 {
						writeLimit = 40000
						limitSource = "mixed-default"
					}
				}
			}
			var totalRead int64
			var totalWrite int64
			var provisionedTableCount int64
			for name, t := range tables {
				billingMode := dynamodbtypes.BillingModeProvisioned
				if t.BillingModeSummary != nil && t.BillingModeSummary.BillingMode != "" {
					billingMode = t.BillingModeSummary.BillingMode
				}
				if billingMode == dynamodbtypes.BillingModePayPerRequest {
					continue
				}
				provisionedTableCount++
				if t.ProvisionedThroughput == nil || t.ProvisionedThroughput.ReadCapacityUnits == nil || t.ProvisionedThroughput.WriteCapacityUnits == nil {
					return []ConfigResource{{
						ID:      name,
						Passing: false,
						Detail:  "Provisioned table missing throughput values",
					}}, nil
				}
				totalRead += *t.ProvisionedThroughput.ReadCapacityUnits
				totalWrite += *t.ProvisionedThroughput.WriteCapacityUnits
				for _, gsi := range t.GlobalSecondaryIndexes {
					if gsi.ProvisionedThroughput == nil || gsi.ProvisionedThroughput.ReadCapacityUnits == nil || gsi.ProvisionedThroughput.WriteCapacityUnits == nil {
						continue
					}
					totalRead += *gsi.ProvisionedThroughput.ReadCapacityUnits
					totalWrite += *gsi.ProvisionedThroughput.WriteCapacityUnits
				}
			}
			if provisionedTableCount == 0 {
				return []ConfigResource{{ID: "account", Passing: true, Detail: "No provisioned throughput tables found"}}, nil
			}
			if readLimit <= 0 || writeLimit <= 0 || maxUsagePercent <= 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "Invalid throughput limit/threshold configuration"}}, nil
			}
			readUsage := (totalRead * 100) / readLimit
			writeUsage := (totalWrite * 100) / writeLimit
			ok := readUsage <= maxUsagePercent && writeUsage <= maxUsagePercent
			return []ConfigResource{{
				ID:      "account",
				Passing: ok,
				Detail: fmt.Sprintf("Provisioned throughput usage read=%d%% (%d/%d), write=%d%% (%d/%d), threshold=%d%%, limitsSource=%s",
					readUsage, totalRead, readLimit, writeUsage, totalWrite, writeLimit, maxUsagePercent, limitSource),
			}}, nil
		},
	))

	// Backup-related DynamoDB checks
	checker.Register(ConfigCheck(
		"dynamodb-in-backup-plan",
		"Checks whether Amazon DynamoDB table is present in AWS Backup Plans. The rule is NON_COMPLIANT if Amazon DynamoDB tables are not present in any AWS Backup plan.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tables {
				id := "unknown"
				if t.TableArn != nil {
					id = *t.TableArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"dynamodb-resources-protected-by-backup-plan",
		"Checks if Amazon DynamoDB tables are protected by a backup plan. The rule is NON_COMPLIANT if the DynamoDB Table is not covered by a backup plan.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tables {
				id := "unknown"
				if t.TableArn != nil {
					id = *t.TableArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"dynamodb-last-backup-recovery-point-created",
		"Checks if a recovery point was created for Amazon DynamoDB Tables within the specified period. The rule is NON_COMPLIANT if the DynamoDB Table does not have a corresponding recovery point created within the specified time period.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tables {
				arn := ""
				if t.TableArn != nil {
					arn = *t.TableArn
				}
				ok, detail := backupRecencyResult(rps[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"dynamodb-meets-restore-time-target",
		"Checks if the restore time of Amazon DynamoDB Tables meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of a DynamoDB Table is greater than maxRestoreTime minutes.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tables {
				arn := ""
				if t.TableArn != nil {
					arn = *t.TableArn
				}
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
}

func dynamodbInt64Env(envVar string, defaultValue int64) int64 {
	value := strings.TrimSpace(os.Getenv(envVar))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return defaultValue
	}
	return parsed
}
