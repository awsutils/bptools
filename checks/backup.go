package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/backup"
)

const backupMinRetentionDays int64 = 35
const backupMaxFrequencyHours int64 = 24

func RegisterBackupChecks(d *awsdata.Data) {
	// backup-plan-min-frequency-and-min-retention-check
	checker.Register(ConfigCheck(
		"backup-plan-min-frequency-and-min-retention-check",
		"Checks if a backup plan has a backup rule that satisfies the required frequency and retention period. The rule is NON_COMPLIANT if recovery points are not created at least as often as the specified frequency or expire before the specified period.",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			plans, err := d.BackupPlanDetails.Get()
			if err != nil {
				return nil, err
			}
			maxFreqHours := backupMaxFrequencyHours
			if v := strings.TrimSpace(os.Getenv("BPTOOLS_BACKUP_MAX_FREQUENCY_HOURS")); v != "" {
				if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
					maxFreqHours = int64(parsed)
				}
			}
			var res []ConfigResource
			for id, plan := range plans {
				ok := true
				evaluatedRules := 0
				nonCompliantRules := 0
				for _, rule := range plan.Rules {
					evaluatedRules++
					freqOK := false
					if rule.ScheduleExpression != nil && strings.TrimSpace(*rule.ScheduleExpression) != "" {
						freqOK = backupScheduleWithinHours(*rule.ScheduleExpression, maxFreqHours)
					}
					retentionOK := rule.Lifecycle != nil && rule.Lifecycle.DeleteAfterDays != nil && *rule.Lifecycle.DeleteAfterDays >= backupMinRetentionDays
					if !(freqOK && retentionOK) {
						nonCompliantRules++
					}
				}
				if evaluatedRules == 0 {
					ok = false
				} else {
					ok = nonCompliantRules == 0
				}
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail: fmt.Sprintf("Rules compliant: %d/%d (retention >= %d days, schedule <= every %d hours)",
						evaluatedRules-nonCompliantRules, evaluatedRules, backupMinRetentionDays, maxFreqHours),
				})
			}
			return res, nil
		},
	))

	// backup-recovery-point-encrypted
	checker.Register(EncryptionCheck(
		"backup-recovery-point-encrypted",
		"Checks if a recovery point is encrypted. The rule is NON_COMPLIANT if the recovery point is not encrypted.",
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
		"Checks if a recovery point expires no earlier than after the specified period. The rule is NON_COMPLIANT if the recovery point has a retention point that is less than the required retention period.",
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
		"Checks if a backup vault has an attached resource-based policy which prevents deletion of recovery points. The rule is NON_COMPLIANT if the Backup Vault does not have resource-based policies or has policies without a suitable 'Deny' statement (statement with backup:DeleteRecoveryPoint, backup:UpdateRecoveryPointLifecycle, and backup:PutBackupVaultAccessPolicy permissions).",
		"backup",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vaults, err := d.BackupVaults.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, vault := range vaults {
				id := "unknown"
				if vault.BackupVaultName != nil {
					id = *vault.BackupVaultName
				}
				if vault.BackupVaultName == nil || strings.TrimSpace(*vault.BackupVaultName) == "" {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing BackupVaultName"})
					continue
				}
				out, err := d.Clients.Backup.GetBackupVaultAccessPolicy(d.Ctx, &backup.GetBackupVaultAccessPolicyInput{
					BackupVaultName: vault.BackupVaultName,
				})
				if err != nil || out.Policy == nil || strings.TrimSpace(*out.Policy) == "" {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Backup vault access policy missing"})
					continue
				}
				ok := backupVaultPolicyDeniesManualDelete(*out.Policy)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Policy denies manual delete: %v", ok)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"storagegateway-resources-protected-by-backup-plan",
		"Checks if AWS Storage Gateway volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Storage Gateway volume is not covered by a backup plan.",
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
		"Checks if a recovery point was created for AWS Storage Gateway volumes. The rule is NON_COMPLIANT if the Storage Gateway volume does not have a corresponding recovery point created within the specified time period.",
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
				ok, detail := backupRecencyResult(points[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"storagegateway-resources-in-logically-air-gapped-vault",
		"Checks if AWS Storage Gateway volumes are in a logically air-gapped vault. The rule is NON_COMPLIANT if an AWS Storage Gateway volume is not in a logically air-gapped vault within the specified time period.",
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
				ok, detail := airGappedRecencyResult(points[arn], backupAirGappedRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"virtualmachine-resources-protected-by-backup-plan",
		"Checks if AWS Backup-Gateway VirtualMachines are protected by a backup plan. The rule is NON_COMPLIANT if the Backup-Gateway VirtualMachine is not covered by a backup plan.",
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
		"Checks if a recovery point was created for AWS Backup-Gateway VirtualMachines. The rule is NON_COMPLIANT if an AWS Backup-Gateway VirtualMachines does not have a corresponding recovery point created within the specified time period.",
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
				ok, detail := backupRecencyResult(points[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"virtualmachine-resources-in-logically-air-gapped-vault",
		"Checks if AWS Backup-Gateway VirtualMachines are in a logically air-gapped vault. The rule is NON_COMPLIANT if an AWS Backup-Gateway VirtualMachines is not in a logically air-gapped vault within the specified time period.",
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
				ok, detail := airGappedRecencyResult(points[arn], backupAirGappedRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
}

func backupScheduleWithinHours(expression string, maxHours int64) bool {
	exp := strings.ToLower(strings.TrimSpace(expression))
	if exp == "" || maxHours <= 0 {
		return false
	}
	if strings.HasPrefix(exp, "rate(") && strings.HasSuffix(exp, ")") {
		body := strings.TrimSuffix(strings.TrimPrefix(exp, "rate("), ")")
		parts := strings.Fields(body)
		if len(parts) != 2 {
			return false
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n <= 0 {
			return false
		}
		unit := parts[1]
		switch unit {
		case "minute", "minutes":
			return int64(n) <= maxHours*60
		case "hour", "hours":
			return int64(n) <= maxHours
		case "day", "days":
			return int64(n)*24 <= maxHours
		default:
			return false
		}
	}
	if strings.HasPrefix(exp, "cron(") && strings.HasSuffix(exp, ")") {
		body := strings.TrimSuffix(strings.TrimPrefix(exp, "cron("), ")")
		fields := strings.Fields(body)
		if len(fields) < 2 {
			return false
		}
		hourField := strings.TrimSpace(fields[1])
		if hourField == "*" {
			return true
		}
		if strings.Contains(hourField, "/") {
			parts := strings.Split(hourField, "/")
			if len(parts) == 2 {
				step, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				return err == nil && step > 0 && int64(step) <= maxHours
			}
			return false
		}
		if strings.Contains(hourField, ",") {
			count := 0
			for _, p := range strings.Split(hourField, ",") {
				if strings.TrimSpace(p) != "" {
					count++
				}
			}
			if count > 0 {
				return 24/int64(count) <= maxHours
			}
			return false
		}
		if _, err := strconv.Atoi(hourField); err == nil {
			return maxHours >= 24
		}
	}
	return false
}

type backupPolicyDocument struct {
	Statement []backupPolicyStatement `json:"Statement"`
}

type backupPolicyStatement struct {
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Principal interface{} `json:"Principal"`
}

func backupVaultPolicyDeniesManualDelete(policy string) bool {
	var doc backupPolicyDocument
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return false
	}
	requiredActions := []string{
		"backup:deleterecoverypoint",
		"backup:updaterecoverypointlifecycle",
		"backup:putbackupvaultaccesspolicy",
	}
	denied := make(map[string]bool, len(requiredActions))
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "Deny") {
			continue
		}
		if !policyPrincipalIsWildcard(stmt.Principal) {
			continue
		}
		for _, action := range policyActions(stmt.Action) {
			a := strings.ToLower(strings.TrimSpace(action))
			if a == "backup:*" || a == "*" {
				return true
			}
			for _, req := range requiredActions {
				if a == req {
					denied[req] = true
				}
			}
		}
	}
	for _, req := range requiredActions {
		if !denied[req] {
			return false
		}
	}
	return len(denied) > 0
}

func policyPrincipalIsWildcard(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return strings.TrimSpace(p) == "*"
	case map[string]interface{}:
		for _, value := range p {
			switch v := value.(type) {
			case string:
				if strings.TrimSpace(v) == "*" {
					return true
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func policyActions(action interface{}) []string {
	switch v := action.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func resourceTypeMatch(t *string, needle string) bool {
	if t == nil {
		return false
	}
	return strings.Contains(strings.ToLower(*t), needle)
}
