package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

const backupMinRetentionDays int64 = 35

func RegisterBackupChecks(d *awsdata.Data) {
	// backup-plan-min-frequency-and-min-retention-check
	checker.Register(ConfigCheck(
		"backup-plan-min-frequency-and-min-retention-check",
		"This rule checks backup plan minimum frequency and retention.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			plans, err := d.BackupPlanDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, plan := range plans {
				ok := false
				for _, rule := range plan.Rules {
					if rule.ScheduleExpression == nil || *rule.ScheduleExpression == "" {
						continue
					}
					if rule.Lifecycle != nil && rule.Lifecycle.DeleteAfterDays != nil && *rule.Lifecycle.DeleteAfterDays >= backupMinRetentionDays {
						ok = true
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Min retention >= %d days", backupMinRetentionDays)})
			}
			return res, nil
		},
	))

	// backup-recovery-point-encrypted
	checker.Register(EncryptionCheck(
		"backup-recovery-point-encrypted",
		"This rule checks backup recovery point encrypted.",
		"backup",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			rps, err := d.BackupRecoveryPoints.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for vault, items := range rps {
				for _, rp := range items {
					id := vault
					if rp.RecoveryPointArn != nil {
						id = *rp.RecoveryPointArn
					}
					res = append(res, EncryptionResource{ID: id, Encrypted: rp.IsEncrypted})
				}
			}
			return res, nil
		},
	))

	// backup-recovery-point-minimum-retention-check
	checker.Register(ConfigCheck(
		"backup-recovery-point-minimum-retention-check",
		"This rule checks backup recovery point minimum retention.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for vault, items := range rps {
				for _, rp := range items {
					id := vault
					if rp.RecoveryPointArn != nil {
						id = *rp.RecoveryPointArn
					}
					ret := int64(0)
					if rp.Lifecycle != nil && rp.Lifecycle.DeleteAfterDays != nil {
						ret = *rp.Lifecycle.DeleteAfterDays
					}
					ok := ret >= backupMinRetentionDays
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeleteAfterDays: %d", ret)})
				}
			}
			return res, nil
		},
	))

	// backup-recovery-point-manual-deletion-disabled
	checker.Register(ConfigCheck(
		"backup-recovery-point-manual-deletion-disabled",
		"This rule checks backup recovery point manual deletion disabled.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			locks, err := d.BackupVaultLockConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for vault, lock := range locks {
				ok := lock.MinRetentionDays != nil && *lock.MinRetentionDays > 0
				res = append(res, ConfigResource{ID: vault, Passing: ok, Detail: fmt.Sprintf("MinRetentionDays: %v", lock.MinRetentionDays)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"storagegateway-resources-protected-by-backup-plan",
		"This rule checks storagegateway resources protected by backup plan.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "storagegateway") {
					continue
				}
				res = append(res, ConfigResource{ID: arn, Passing: true, Detail: "Protected resource"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"storagegateway-last-backup-recovery-point-created",
		"This rule checks storagegateway last backup recovery point created.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			points, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "storagegateway") {
					continue
				}
				ok := len(points[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Recovery points: %d", len(points[arn]))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"storagegateway-resources-in-logically-air-gapped-vault",
		"This rule checks storagegateway resources in logically air gapped vault.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			points, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			locks, err := d.BackupVaultLockConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "storagegateway") {
					continue
				}
				ok := false
				for _, rp := range points[arn] {
					if rp.BackupVaultName != nil {
						if _, has := locks[*rp.BackupVaultName]; has {
							ok = true
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points in locked vault"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"virtualmachine-resources-protected-by-backup-plan",
		"This rule checks virtualmachine resources protected by backup plan.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "virtualmachine") && !resourceTypeMatch(r.ResourceType, "vmware") {
					continue
				}
				res = append(res, ConfigResource{ID: arn, Passing: true, Detail: "Protected resource"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"virtualmachine-last-backup-recovery-point-created",
		"This rule checks virtualmachine last backup recovery point created.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			points, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "virtualmachine") && !resourceTypeMatch(r.ResourceType, "vmware") {
					continue
				}
				ok := len(points[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Recovery points: %d", len(points[arn]))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"virtualmachine-resources-in-logically-air-gapped-vault",
		"This rule checks virtualmachine resources in logically air gapped vault.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			points, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			locks, err := d.BackupVaultLockConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, r := range resources {
				if !resourceTypeMatch(r.ResourceType, "virtualmachine") && !resourceTypeMatch(r.ResourceType, "vmware") {
					continue
				}
				ok := false
				for _, rp := range points[arn] {
					if rp.BackupVaultName != nil {
						if _, has := locks[*rp.BackupVaultName]; has {
							ok = true
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points in locked vault"})
			}
			return res, nil
		},
	))
}

func resourceTypeMatch(t *string, needle string) bool {
	if t == nil {
		return false
	}
	return strings.Contains(strings.ToLower(*t), needle)
}
