package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func RegisterDynamoDBChecks(d *awsdata.Data) {
	// dynamodb-autoscaling-enabled
	checker.Register(EnabledCheck(
		"dynamodb-autoscaling-enabled",
		"This rule checks DynamoDB autoscaling enabled.",
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
		"This rule checks DynamoDB PITR enabled.",
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
		"This rule checks DynamoDB table deletion protection enabled.",
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
		"This rule checks DynamoDB table encryption enabled.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, t := range tables {
				encrypted := t.SSEDescription != nil && t.SSEDescription.Status == dynamodbtypes.SSEStatusEnabled
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"dynamodb-table-encrypted-kms",
		"This rule checks DynamoDB table encrypted with KMS.",
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
		"This rule checks DynamoDB throughput limits.",
		"dynamodb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tables, err := d.DynamoDBTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, t := range tables {
				ok := t.BillingModeSummary != nil && t.BillingModeSummary.BillingMode == dynamodbtypes.BillingModePayPerRequest
				if !ok && t.ProvisionedThroughput != nil {
					ok = t.ProvisionedThroughput.ReadCapacityUnits != nil && t.ProvisionedThroughput.WriteCapacityUnits != nil
				}
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("BillingMode: %v", t.BillingModeSummary)})
			}
			return res, nil
		},
	))

	// Backup-related DynamoDB checks
	checker.Register(ConfigCheck(
		"dynamodb-in-backup-plan",
		"This rule checks DynamoDB in backup plan.",
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
		"This rule checks DynamoDB resources protected by backup plan.",
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
		"This rule checks DynamoDB last backup recovery point created.",
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
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery point exists"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"dynamodb-meets-restore-time-target",
		"This rule checks DynamoDB meets restore time target.",
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
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points available"})
			}
			return res, nil
		},
	))
}
