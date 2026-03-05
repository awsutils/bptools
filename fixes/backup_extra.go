package fixes

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	mb05MinRetentionDays  int64         = 35
	mb05MaxFrequencyHours int64         = 24
	mb05RecencyWindow     time.Duration = 24 * time.Hour

	mb05ManagedPlanName        = "bptools-auto-backup-plan"
	mb05ManagedVaultName       = "bptools-managed-backup-vault"
	mb05EncryptedVaultName     = "bptools-encrypted-backup-vault"
	mb05AirGappedVaultName     = "bptools-air-gapped-backup-vault"
	mb05DenyStatementSID       = "BPToolsDenyBackupRecoveryPointDeletion"
	mb05DefaultScheduleExpr    = "cron(0 */12 * * ? *)"
	mb05DefaultSelectionPrefix = "bptools-selection"
)

func registerMultiBatch05(d *awsdata.Data) {
	fix.Register(&backupPlanMinFrequencyAndMinRetentionFix{clients: d.Clients})
	fix.Register(&backupRecoveryPointEncryptedFix{clients: d.Clients})
	fix.Register(&backupRecoveryPointMinimumRetentionFix{clients: d.Clients})
	fix.Register(&backupRecoveryPointManualDeletionDisabledFix{clients: d.Clients})
	fix.Register(&storageGatewayResourcesProtectedByBackupPlanFix{clients: d.Clients})
	fix.Register(&storageGatewayLastBackupRecoveryPointCreatedFix{clients: d.Clients})
	fix.Register(&storageGatewayResourcesInLogicallyAirGappedVaultFix{clients: d.Clients})
	fix.Register(&virtualMachineResourcesProtectedByBackupPlanFix{clients: d.Clients})
	fix.Register(&virtualMachineLastBackupRecoveryPointCreatedFix{clients: d.Clients})
	fix.Register(&virtualMachineResourcesInLogicallyAirGappedVaultFix{clients: d.Clients})
}

type backupPlanMinFrequencyAndMinRetentionFix struct{ clients *awsdata.Clients }

func (f *backupPlanMinFrequencyAndMinRetentionFix) CheckID() string {
	return "backup-plan-min-frequency-and-min-retention-check"
}
func (f *backupPlanMinFrequencyAndMinRetentionFix) Description() string {
	return "Ensure backup plan rules run at least daily and keep recovery points for at least 35 days"
}
func (f *backupPlanMinFrequencyAndMinRetentionFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *backupPlanMinFrequencyAndMinRetentionFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *backupPlanMinFrequencyAndMinRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	planID := backupPlanIDFromResourceID(resourceID)
	if planID == "" {
		base.Status = fix.FixSkipped
		base.Message = "unable to determine backup plan ID from resource ID"
		return base
	}

	out, err := f.clients.Backup.GetBackupPlan(fctx.Ctx, &backup.GetBackupPlanInput{BackupPlanId: aws.String(planID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get backup plan: " + err.Error()
		return base
	}
	if out.BackupPlan == nil || out.BackupPlan.BackupPlanName == nil || len(out.BackupPlan.Rules) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "backup plan has no modifiable rules"
		return base
	}

	changed := 0
	rules := make([]backuptypes.BackupRuleInput, 0, len(out.BackupPlan.Rules))
	for _, r := range out.BackupPlan.Rules {
		ri := backupRuleToInput(r)
		modified := false
		if ri.ScheduleExpression == nil || !backupScheduleWithinHours(*ri.ScheduleExpression, mb05MaxFrequencyHours) {
			ri.ScheduleExpression = aws.String(mb05DefaultScheduleExpr)
			modified = true
		}
		if ri.Lifecycle == nil {
			ri.Lifecycle = &backuptypes.Lifecycle{DeleteAfterDays: aws.Int64(mb05MinRetentionDays)}
			modified = true
		} else {
			current := int64(0)
			if ri.Lifecycle.DeleteAfterDays != nil {
				current = *ri.Lifecycle.DeleteAfterDays
			}
			required := mb05MinRetentionDays
			if ri.Lifecycle.MoveToColdStorageAfterDays != nil {
				coldMin := *ri.Lifecycle.MoveToColdStorageAfterDays + 90
				if coldMin > required {
					required = coldMin
				}
			}
			if current < required {
				ri.Lifecycle.DeleteAfterDays = aws.Int64(required)
				modified = true
			}
		}
		if modified {
			changed++
		}
		rules = append(rules, ri)
	}

	if changed == 0 {
		base.Status = fix.FixSkipped
		base.Message = "backup plan rules already satisfy frequency/retention requirements"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would update %d backup rule(s) in plan %s", changed, planID)}
		return base
	}

	_, err = f.clients.Backup.UpdateBackupPlan(fctx.Ctx, &backup.UpdateBackupPlanInput{
		BackupPlanId: aws.String(planID),
		BackupPlan: &backuptypes.BackupPlanInput{
			BackupPlanName:         out.BackupPlan.BackupPlanName,
			Rules:                  rules,
			AdvancedBackupSettings: out.BackupPlan.AdvancedBackupSettings,
			ScanSettings:           out.BackupPlan.ScanSettings,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update backup plan: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("updated %d backup rule(s) in plan %s", changed, planID)}
	return base
}

type backupRecoveryPointEncryptedFix struct{ clients *awsdata.Clients }

func (f *backupRecoveryPointEncryptedFix) CheckID() string { return "backup-recovery-point-encrypted" }
func (f *backupRecoveryPointEncryptedFix) Description() string {
	return "Copy unencrypted recovery point into an encrypted backup vault"
}
func (f *backupRecoveryPointEncryptedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *backupRecoveryPointEncryptedFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *backupRecoveryPointEncryptedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	rpArn := strings.TrimSpace(resourceID)
	if !strings.Contains(rpArn, ":recovery-point:") {
		base.Status = fix.FixSkipped
		base.Message = "resource ID is not a recovery point ARN"
		return base
	}

	rp, err := findRecoveryPointByARN(fctx.Ctx, f.clients, rpArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "find recovery point: " + err.Error()
		return base
	}
	if rp == nil || rp.BackupVaultName == nil || strings.TrimSpace(*rp.BackupVaultName) == "" {
		base.Status = fix.FixSkipped
		base.Message = "unable to locate source backup vault for recovery point"
		return base
	}
	if rp.IsEncrypted {
		base.Status = fix.FixSkipped
		base.Message = "recovery point is already encrypted"
		return base
	}

	destVaultARN, err := ensureStandardBackupVault(fctx.Ctx, f.clients, mb05EncryptedVaultName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure encrypted backup vault: " + err.Error()
		return base
	}
	roleArn, err := defaultBackupServiceRoleARN(fctx.Ctx, f.clients, rpArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve backup service role ARN: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would copy recovery point %s from vault %s to encrypted vault %s", rpArn, aws.ToString(rp.BackupVaultName), mb05EncryptedVaultName)}
		return base
	}

	_, err = f.clients.Backup.StartCopyJob(fctx.Ctx, &backup.StartCopyJobInput{
		RecoveryPointArn:          aws.String(rpArn),
		SourceBackupVaultName:     rp.BackupVaultName,
		DestinationBackupVaultArn: aws.String(destVaultARN),
		IamRoleArn:                aws.String(roleArn),
		Lifecycle:                 rp.Lifecycle,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start copy job: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("started copy job for %s into encrypted vault %s", rpArn, mb05EncryptedVaultName)}
	return base
}

type backupRecoveryPointMinimumRetentionFix struct{ clients *awsdata.Clients }

func (f *backupRecoveryPointMinimumRetentionFix) CheckID() string {
	return "backup-recovery-point-minimum-retention-check"
}
func (f *backupRecoveryPointMinimumRetentionFix) Description() string {
	return "Set recovery point retention to at least 35 days"
}
func (f *backupRecoveryPointMinimumRetentionFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *backupRecoveryPointMinimumRetentionFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *backupRecoveryPointMinimumRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	rpArn := strings.TrimSpace(resourceID)
	if !strings.Contains(rpArn, ":recovery-point:") {
		base.Status = fix.FixSkipped
		base.Message = "resource ID is not a recovery point ARN"
		return base
	}

	rp, err := findRecoveryPointByARN(fctx.Ctx, f.clients, rpArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "find recovery point: " + err.Error()
		return base
	}
	if rp == nil || rp.BackupVaultName == nil || strings.TrimSpace(*rp.BackupVaultName) == "" {
		base.Status = fix.FixSkipped
		base.Message = "unable to locate source backup vault for recovery point"
		return base
	}

	ret := int64(0)
	if rp.Lifecycle != nil && rp.Lifecycle.DeleteAfterDays != nil {
		ret = *rp.Lifecycle.DeleteAfterDays
	}
	required := mb05MinRetentionDays
	if rp.Lifecycle != nil && rp.Lifecycle.MoveToColdStorageAfterDays != nil {
		coldMin := *rp.Lifecycle.MoveToColdStorageAfterDays + 90
		if coldMin > required {
			required = coldMin
		}
	}
	if ret >= required {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("recovery point retention already compliant (%d days)", ret)
		return base
	}

	newLifecycle := &backuptypes.Lifecycle{DeleteAfterDays: aws.Int64(required)}
	if rp.Lifecycle != nil {
		newLifecycle.MoveToColdStorageAfterDays = rp.Lifecycle.MoveToColdStorageAfterDays
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set retention for %s to %d days", rpArn, required)}
		return base
	}

	_, err = f.clients.Backup.UpdateRecoveryPointLifecycle(fctx.Ctx, &backup.UpdateRecoveryPointLifecycleInput{
		BackupVaultName:  rp.BackupVaultName,
		RecoveryPointArn: aws.String(rpArn),
		Lifecycle:        newLifecycle,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update recovery point lifecycle: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set retention for %s to %d days", rpArn, required)}
	return base
}

type backupRecoveryPointManualDeletionDisabledFix struct{ clients *awsdata.Clients }

func (f *backupRecoveryPointManualDeletionDisabledFix) CheckID() string {
	return "backup-recovery-point-manual-deletion-disabled"
}
func (f *backupRecoveryPointManualDeletionDisabledFix) Description() string {
	return "Attach backup vault policy that denies manual recovery-point deletion"
}
func (f *backupRecoveryPointManualDeletionDisabledFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *backupRecoveryPointManualDeletionDisabledFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *backupRecoveryPointManualDeletionDisabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	vaultName := backupVaultNameFromResourceID(resourceID)
	if vaultName == "" {
		base.Status = fix.FixSkipped
		base.Message = "unable to determine backup vault name from resource ID"
		return base
	}

	var currentPolicy string
	out, err := f.clients.Backup.GetBackupVaultAccessPolicy(fctx.Ctx, &backup.GetBackupVaultAccessPolicyInput{BackupVaultName: aws.String(vaultName)})
	if err != nil {
		if !isNotFoundErr(err) {
			base.Status = fix.FixFailed
			base.Message = "get backup vault access policy: " + err.Error()
			return base
		}
	} else if out.Policy != nil {
		currentPolicy = *out.Policy
	}

	if backupVaultPolicyDeniesManualDelete(currentPolicy) {
		base.Status = fix.FixSkipped
		base.Message = "backup vault policy already denies manual recovery-point deletion"
		return base
	}

	mergedPolicy, err := addManualDeleteDenyPolicyStatement(currentPolicy)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "build updated policy document: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set backup vault access policy deny statement on vault %s", vaultName)}
		return base
	}

	_, err = f.clients.Backup.PutBackupVaultAccessPolicy(fctx.Ctx, &backup.PutBackupVaultAccessPolicyInput{
		BackupVaultName: aws.String(vaultName),
		Policy:          aws.String(mergedPolicy),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put backup vault access policy: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("updated backup vault policy to deny manual deletion in vault %s", vaultName)}
	return base
}

type storageGatewayResourcesProtectedByBackupPlanFix struct{ clients *awsdata.Clients }

func (f *storageGatewayResourcesProtectedByBackupPlanFix) CheckID() string {
	return "storagegateway-resources-protected-by-backup-plan"
}
func (f *storageGatewayResourcesProtectedByBackupPlanFix) Description() string {
	return "Add Storage Gateway resource to managed AWS Backup plan"
}
func (f *storageGatewayResourcesProtectedByBackupPlanFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *storageGatewayResourcesProtectedByBackupPlanFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *storageGatewayResourcesProtectedByBackupPlanFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyResourceProtectedByBackupPlanFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "storagegateway")
}

type storageGatewayLastBackupRecoveryPointCreatedFix struct{ clients *awsdata.Clients }

func (f *storageGatewayLastBackupRecoveryPointCreatedFix) CheckID() string {
	return "storagegateway-last-backup-recovery-point-created"
}
func (f *storageGatewayLastBackupRecoveryPointCreatedFix) Description() string {
	return "Start an on-demand backup for Storage Gateway resource"
}
func (f *storageGatewayLastBackupRecoveryPointCreatedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *storageGatewayLastBackupRecoveryPointCreatedFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *storageGatewayLastBackupRecoveryPointCreatedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyLastBackupRecoveryPointFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "storagegateway")
}

type storageGatewayResourcesInLogicallyAirGappedVaultFix struct{ clients *awsdata.Clients }

func (f *storageGatewayResourcesInLogicallyAirGappedVaultFix) CheckID() string {
	return "storagegateway-resources-in-logically-air-gapped-vault"
}
func (f *storageGatewayResourcesInLogicallyAirGappedVaultFix) Description() string {
	return "Copy Storage Gateway recovery point to a logically air-gapped vault"
}
func (f *storageGatewayResourcesInLogicallyAirGappedVaultFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *storageGatewayResourcesInLogicallyAirGappedVaultFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *storageGatewayResourcesInLogicallyAirGappedVaultFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyAirGappedVaultFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "storagegateway")
}

type virtualMachineResourcesProtectedByBackupPlanFix struct{ clients *awsdata.Clients }

func (f *virtualMachineResourcesProtectedByBackupPlanFix) CheckID() string {
	return "virtualmachine-resources-protected-by-backup-plan"
}
func (f *virtualMachineResourcesProtectedByBackupPlanFix) Description() string {
	return "Add Backup Gateway virtual machine resource to managed AWS Backup plan"
}
func (f *virtualMachineResourcesProtectedByBackupPlanFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *virtualMachineResourcesProtectedByBackupPlanFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *virtualMachineResourcesProtectedByBackupPlanFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyResourceProtectedByBackupPlanFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "virtualmachine")
}

type virtualMachineLastBackupRecoveryPointCreatedFix struct{ clients *awsdata.Clients }

func (f *virtualMachineLastBackupRecoveryPointCreatedFix) CheckID() string {
	return "virtualmachine-last-backup-recovery-point-created"
}
func (f *virtualMachineLastBackupRecoveryPointCreatedFix) Description() string {
	return "Start an on-demand backup for Backup Gateway virtual machine resource"
}
func (f *virtualMachineLastBackupRecoveryPointCreatedFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *virtualMachineLastBackupRecoveryPointCreatedFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *virtualMachineLastBackupRecoveryPointCreatedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyLastBackupRecoveryPointFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "virtualmachine")
}

type virtualMachineResourcesInLogicallyAirGappedVaultFix struct{ clients *awsdata.Clients }

func (f *virtualMachineResourcesInLogicallyAirGappedVaultFix) CheckID() string {
	return "virtualmachine-resources-in-logically-air-gapped-vault"
}
func (f *virtualMachineResourcesInLogicallyAirGappedVaultFix) Description() string {
	return "Copy Backup Gateway virtual machine recovery point to a logically air-gapped vault"
}
func (f *virtualMachineResourcesInLogicallyAirGappedVaultFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *virtualMachineResourcesInLogicallyAirGappedVaultFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *virtualMachineResourcesInLogicallyAirGappedVaultFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	return applyAirGappedVaultFix(fctx, f.clients, f.CheckID(), f.Impact(), f.Severity(), resourceID, "virtualmachine")
}

func applyResourceProtectedByBackupPlanFix(fctx fix.FixContext, clients *awsdata.Clients, checkID string, impact fix.ImpactType, severity fix.SeverityLevel, resourceID, expectedType string) fix.FixResult {
	base := fix.FixResult{CheckID: checkID, ResourceID: resourceID, Impact: impact, Severity: severity}
	resourceArn := strings.TrimSpace(resourceID)
	if resourceArn == "" || !strings.HasPrefix(strings.ToLower(resourceArn), "arn:") {
		base.Status = fix.FixSkipped
		base.Message = "resource ID is not a valid ARN"
		return base
	}
	if !backupResourceTypeMatch(resourceArn, expectedType) {
		base.Status = fix.FixSkipped
		base.Message = "resource ARN does not match expected resource type"
		return base
	}

	protected, err := isResourceAlreadyProtected(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list protected resources: " + err.Error()
		return base
	}
	if protected {
		base.Status = fix.FixSkipped
		base.Message = "resource is already protected by AWS Backup"
		return base
	}

	roleArn, err := defaultBackupServiceRoleARN(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve backup service role ARN: " + err.Error()
		return base
	}
	planID, err := ensureManagedBackupPlan(fctx.Ctx, clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure managed backup plan: " + err.Error()
		return base
	}
	alreadySelected, err := isResourceInBackupPlanSelections(fctx.Ctx, clients, planID, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "inspect backup plan selections: " + err.Error()
		return base
	}
	if alreadySelected {
		base.Status = fix.FixSkipped
		base.Message = "resource already included in a backup plan selection"
		return base
	}

	selectionName := fmt.Sprintf("%s-%d", mb05DefaultSelectionPrefix, time.Now().Unix())
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would create backup selection %s in plan %s for resource %s", selectionName, planID, resourceArn)}
		return base
	}

	_, err = clients.Backup.CreateBackupSelection(fctx.Ctx, &backup.CreateBackupSelectionInput{
		BackupPlanId: aws.String(planID),
		BackupSelection: &backuptypes.BackupSelection{
			SelectionName: aws.String(selectionName),
			IamRoleArn:    aws.String(roleArn),
			Resources:     []string{resourceArn},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create backup selection: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("created backup selection %s in plan %s for resource %s", selectionName, planID, resourceArn)}
	return base
}

func applyLastBackupRecoveryPointFix(fctx fix.FixContext, clients *awsdata.Clients, checkID string, impact fix.ImpactType, severity fix.SeverityLevel, resourceID, expectedType string) fix.FixResult {
	base := fix.FixResult{CheckID: checkID, ResourceID: resourceID, Impact: impact, Severity: severity}
	resourceArn := strings.TrimSpace(resourceID)
	if resourceArn == "" || !strings.HasPrefix(strings.ToLower(resourceArn), "arn:") {
		base.Status = fix.FixSkipped
		base.Message = "resource ID is not a valid ARN"
		return base
	}
	if !backupResourceTypeMatch(resourceArn, expectedType) {
		base.Status = fix.FixSkipped
		base.Message = "resource ARN does not match expected resource type"
		return base
	}

	points, err := listRecoveryPointsByResource(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list recovery points by resource: " + err.Error()
		return base
	}
	if latest, ok := latestRecoveryPointByResource(points, false); ok && latest.CreationDate != nil {
		if time.Since(*latest.CreationDate) <= mb05RecencyWindow {
			base.Status = fix.FixSkipped
			base.Message = "latest recovery point is already within recency window"
			return base
		}
	}

	_, err = ensureStandardBackupVault(fctx.Ctx, clients, mb05ManagedVaultName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure managed backup vault: " + err.Error()
		return base
	}
	roleArn, err := defaultBackupServiceRoleARN(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve backup service role ARN: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would start on-demand backup for %s into vault %s", resourceArn, mb05ManagedVaultName)}
		return base
	}

	_, err = clients.Backup.StartBackupJob(fctx.Ctx, &backup.StartBackupJobInput{
		BackupVaultName: aws.String(mb05ManagedVaultName),
		IamRoleArn:      aws.String(roleArn),
		ResourceArn:     aws.String(resourceArn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start backup job: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("started on-demand backup for %s into vault %s", resourceArn, mb05ManagedVaultName)}
	return base
}

func applyAirGappedVaultFix(fctx fix.FixContext, clients *awsdata.Clients, checkID string, impact fix.ImpactType, severity fix.SeverityLevel, resourceID, expectedType string) fix.FixResult {
	base := fix.FixResult{CheckID: checkID, ResourceID: resourceID, Impact: impact, Severity: severity}
	resourceArn := strings.TrimSpace(resourceID)
	if resourceArn == "" || !strings.HasPrefix(strings.ToLower(resourceArn), "arn:") {
		base.Status = fix.FixSkipped
		base.Message = "resource ID is not a valid ARN"
		return base
	}
	if !backupResourceTypeMatch(resourceArn, expectedType) {
		base.Status = fix.FixSkipped
		base.Message = "resource ARN does not match expected resource type"
		return base
	}

	points, err := listRecoveryPointsByResource(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list recovery points by resource: " + err.Error()
		return base
	}
	if latestAir, ok := latestRecoveryPointByResource(points, true); ok && latestAir.CreationDate != nil {
		if time.Since(*latestAir.CreationDate) <= mb05RecencyWindow {
			base.Status = fix.FixSkipped
			base.Message = "latest logically air-gapped recovery point is already within recency window"
			return base
		}
	}

	airArn, err := ensureLogicallyAirGappedVault(fctx.Ctx, clients, mb05AirGappedVaultName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure logically air-gapped vault: " + err.Error()
		return base
	}
	roleArn, err := defaultBackupServiceRoleARN(fctx.Ctx, clients, resourceArn)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve backup service role ARN: " + err.Error()
		return base
	}

	latestAny, hasAny := latestRecoveryPointByResource(points, false)
	if hasAny && latestAny.RecoveryPointArn != nil && latestAny.BackupVaultName != nil {
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{fmt.Sprintf("would copy recovery point %s to logically air-gapped vault %s", *latestAny.RecoveryPointArn, mb05AirGappedVaultName)}
			return base
		}
		_, err = clients.Backup.StartCopyJob(fctx.Ctx, &backup.StartCopyJobInput{
			RecoveryPointArn:          latestAny.RecoveryPointArn,
			SourceBackupVaultName:     latestAny.BackupVaultName,
			DestinationBackupVaultArn: aws.String(airArn),
			IamRoleArn:                aws.String(roleArn),
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "start copy job to logically air-gapped vault: " + err.Error()
			return base
		}
		base.Status = fix.FixApplied
		base.Steps = []string{fmt.Sprintf("started copy of recovery point %s to logically air-gapped vault %s", *latestAny.RecoveryPointArn, mb05AirGappedVaultName)}
		return base
	}

	_, err = ensureStandardBackupVault(fctx.Ctx, clients, mb05ManagedVaultName)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure managed backup vault: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would start backup job for %s targeting logically air-gapped vault %s", resourceArn, mb05AirGappedVaultName)}
		return base
	}

	_, err = clients.Backup.StartBackupJob(fctx.Ctx, &backup.StartBackupJobInput{
		BackupVaultName:                  aws.String(mb05ManagedVaultName),
		IamRoleArn:                       aws.String(roleArn),
		ResourceArn:                      aws.String(resourceArn),
		LogicallyAirGappedBackupVaultArn: aws.String(airArn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start backup job targeting logically air-gapped vault: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("started backup job for %s targeting logically air-gapped vault %s", resourceArn, mb05AirGappedVaultName)}
	return base
}

func backupPlanIDFromResourceID(resourceID string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return ""
	}
	if strings.Contains(id, ":plan:") {
		parts := strings.SplitN(id, ":plan:", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	return id
}

func backupVaultNameFromResourceID(resourceID string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return ""
	}
	if strings.Contains(id, ":backup-vault:") {
		parts := strings.SplitN(id, ":backup-vault:", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return id
}

func backupRuleToInput(r backuptypes.BackupRule) backuptypes.BackupRuleInput {
	return backuptypes.BackupRuleInput{
		RuleName:                               r.RuleName,
		TargetBackupVaultName:                  r.TargetBackupVaultName,
		CompletionWindowMinutes:                r.CompletionWindowMinutes,
		CopyActions:                            r.CopyActions,
		EnableContinuousBackup:                 r.EnableContinuousBackup,
		IndexActions:                           r.IndexActions,
		Lifecycle:                              r.Lifecycle,
		RecoveryPointTags:                      r.RecoveryPointTags,
		ScanActions:                            r.ScanActions,
		ScheduleExpression:                     r.ScheduleExpression,
		ScheduleExpressionTimezone:             r.ScheduleExpressionTimezone,
		StartWindowMinutes:                     r.StartWindowMinutes,
		TargetLogicallyAirGappedBackupVaultArn: r.TargetLogicallyAirGappedBackupVaultArn,
	}
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
		switch parts[1] {
		case "minute", "minutes":
			return int64(n) <= maxHours*60
		case "hour", "hours":
			return int64(n) <= maxHours
		case "day", "days":
			return int64(n)*24 <= maxHours
		}
		return false
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

func ensureManagedBackupPlan(ctx context.Context, clients *awsdata.Clients) (string, error) {
	plans, err := listBackupPlans(ctx, clients)
	if err != nil {
		return "", err
	}
	for _, p := range plans {
		if p.BackupPlanName != nil && *p.BackupPlanName == mb05ManagedPlanName && p.BackupPlanId != nil {
			return *p.BackupPlanId, nil
		}
	}

	_, err = ensureStandardBackupVault(ctx, clients, mb05ManagedVaultName)
	if err != nil {
		return "", err
	}

	created, err := clients.Backup.CreateBackupPlan(ctx, &backup.CreateBackupPlanInput{
		BackupPlan: &backuptypes.BackupPlanInput{
			BackupPlanName: aws.String(mb05ManagedPlanName),
			Rules: []backuptypes.BackupRuleInput{{
				RuleName:              aws.String("bptools-daily-rule"),
				TargetBackupVaultName: aws.String(mb05ManagedVaultName),
				ScheduleExpression:    aws.String(mb05DefaultScheduleExpr),
				Lifecycle:             &backuptypes.Lifecycle{DeleteAfterDays: aws.Int64(mb05MinRetentionDays)},
			}},
		},
	})
	if err != nil {
		return "", err
	}
	if created.BackupPlanId == nil || strings.TrimSpace(*created.BackupPlanId) == "" {
		return "", fmt.Errorf("create backup plan returned empty plan ID")
	}
	return *created.BackupPlanId, nil
}

func ensureStandardBackupVault(ctx context.Context, clients *awsdata.Clients, vaultName string) (string, error) {
	desc, err := clients.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: aws.String(vaultName)})
	if err == nil {
		if desc.BackupVaultArn != nil {
			return *desc.BackupVaultArn, nil
		}
		return "", fmt.Errorf("describe backup vault returned empty ARN for %s", vaultName)
	}
	if !isNotFoundErr(err) {
		return "", err
	}
	created, err := clients.Backup.CreateBackupVault(ctx, &backup.CreateBackupVaultInput{BackupVaultName: aws.String(vaultName)})
	if err != nil {
		if isAlreadyExistsErr(err) {
			desc2, derr := clients.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: aws.String(vaultName)})
			if derr != nil {
				return "", derr
			}
			if desc2.BackupVaultArn != nil {
				return *desc2.BackupVaultArn, nil
			}
			return "", fmt.Errorf("backup vault %s exists but ARN not returned", vaultName)
		}
		return "", err
	}
	if created.BackupVaultArn == nil {
		return "", fmt.Errorf("create backup vault returned empty ARN for %s", vaultName)
	}
	return *created.BackupVaultArn, nil
}

func ensureLogicallyAirGappedVault(ctx context.Context, clients *awsdata.Clients, vaultName string) (string, error) {
	desc, err := clients.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: aws.String(vaultName)})
	if err == nil {
		if desc.VaultType != backuptypes.VaultTypeLogicallyAirGappedBackupVault {
			return "", fmt.Errorf("vault %s exists but is not logically air-gapped", vaultName)
		}
		if desc.BackupVaultArn != nil {
			return *desc.BackupVaultArn, nil
		}
		return "", fmt.Errorf("describe backup vault returned empty ARN for %s", vaultName)
	}
	if !isNotFoundErr(err) {
		return "", err
	}
	created, err := clients.Backup.CreateLogicallyAirGappedBackupVault(ctx, &backup.CreateLogicallyAirGappedBackupVaultInput{
		BackupVaultName:  aws.String(vaultName),
		MinRetentionDays: aws.Int64(mb05MinRetentionDays),
		MaxRetentionDays: aws.Int64(mb05MinRetentionDays * 10),
	})
	if err != nil {
		if isAlreadyExistsErr(err) {
			desc2, derr := clients.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: aws.String(vaultName)})
			if derr != nil {
				return "", derr
			}
			if desc2.VaultType != backuptypes.VaultTypeLogicallyAirGappedBackupVault {
				return "", fmt.Errorf("vault %s exists but is not logically air-gapped", vaultName)
			}
			if desc2.BackupVaultArn != nil {
				return *desc2.BackupVaultArn, nil
			}
			return "", fmt.Errorf("backup vault %s exists but ARN not returned", vaultName)
		}
		return "", err
	}
	if created.BackupVaultArn == nil {
		return "", fmt.Errorf("create logically air-gapped vault returned empty ARN for %s", vaultName)
	}
	return *created.BackupVaultArn, nil
}

func defaultBackupServiceRoleARN(ctx context.Context, clients *awsdata.Clients, fallbackArn string) (string, error) {
	acct := arnPart(fallbackArn, 4)
	if acct == "" {
		idOut, err := clients.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		acct = aws.ToString(idOut.Account)
	}
	if acct == "" {
		return "", fmt.Errorf("unable to determine AWS account ID")
	}
	return "arn:aws:iam::" + acct + ":role/service-role/AWSBackupDefaultServiceRole", nil
}

func arnPart(arn string, idx int) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return strings.TrimSpace(parts[idx])
}

func listBackupPlans(ctx context.Context, clients *awsdata.Clients) ([]backuptypes.BackupPlansListMember, error) {
	var out []backuptypes.BackupPlansListMember
	p := backup.NewListBackupPlansPaginator(clients.Backup, &backup.ListBackupPlansInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.BackupPlansList...)
	}
	return out, nil
}

func isResourceAlreadyProtected(ctx context.Context, clients *awsdata.Clients, resourceArn string) (bool, error) {
	p := backup.NewListProtectedResourcesPaginator(clients.Backup, &backup.ListProtectedResourcesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return false, err
		}
		for _, r := range page.Results {
			if strings.EqualFold(strings.TrimSpace(aws.ToString(r.ResourceArn)), strings.TrimSpace(resourceArn)) {
				return true, nil
			}
		}
	}
	return false, nil
}

func isResourceInBackupPlanSelections(ctx context.Context, clients *awsdata.Clients, planID, resourceArn string) (bool, error) {
	p := backup.NewListBackupSelectionsPaginator(clients.Backup, &backup.ListBackupSelectionsInput{BackupPlanId: aws.String(planID)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return false, err
		}
		for _, s := range page.BackupSelectionsList {
			if s.SelectionId == nil {
				continue
			}
			g, err := clients.Backup.GetBackupSelection(ctx, &backup.GetBackupSelectionInput{
				BackupPlanId: aws.String(planID),
				SelectionId:  s.SelectionId,
			})
			if err != nil || g.BackupSelection == nil {
				continue
			}
			for _, selArn := range g.BackupSelection.Resources {
				if strings.EqualFold(strings.TrimSpace(selArn), strings.TrimSpace(resourceArn)) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func listRecoveryPointsByResource(ctx context.Context, clients *awsdata.Clients, resourceArn string) ([]backuptypes.RecoveryPointByResource, error) {
	var out []backuptypes.RecoveryPointByResource
	p := backup.NewListRecoveryPointsByResourcePaginator(clients.Backup, &backup.ListRecoveryPointsByResourceInput{ResourceArn: aws.String(resourceArn)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.RecoveryPoints...)
	}
	return out, nil
}

func findRecoveryPointByARN(ctx context.Context, clients *awsdata.Clients, recoveryPointArn string) (*backup.DescribeRecoveryPointOutput, error) {
	vaults, err := listBackupVaults(ctx, clients)
	if err != nil {
		return nil, err
	}
	for _, v := range vaults {
		if v.BackupVaultName == nil {
			continue
		}
		d, err := clients.Backup.DescribeRecoveryPoint(ctx, &backup.DescribeRecoveryPointInput{
			BackupVaultName:  v.BackupVaultName,
			RecoveryPointArn: aws.String(recoveryPointArn),
		})
		if err != nil {
			if isNotFoundErr(err) {
				continue
			}
			continue
		}
		return d, nil
	}
	return nil, nil
}

func listBackupVaults(ctx context.Context, clients *awsdata.Clients) ([]backuptypes.BackupVaultListMember, error) {
	var out []backuptypes.BackupVaultListMember
	p := backup.NewListBackupVaultsPaginator(clients.Backup, &backup.ListBackupVaultsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.BackupVaultList...)
	}
	return out, nil
}

func latestRecoveryPointByResource(points []backuptypes.RecoveryPointByResource, airGappedOnly bool) (backuptypes.RecoveryPointByResource, bool) {
	var latest backuptypes.RecoveryPointByResource
	found := false
	for _, rp := range points {
		if rp.CreationDate == nil {
			continue
		}
		if airGappedOnly && rp.VaultType != backuptypes.VaultTypeLogicallyAirGappedBackupVault {
			continue
		}
		if !found || rp.CreationDate.After(*latest.CreationDate) {
			latest = rp
			found = true
		}
	}
	return latest, found
}

func backupResourceTypeMatch(resourceArn, expectedType string) bool {
	a := strings.ToLower(strings.TrimSpace(resourceArn))
	t := strings.ToLower(strings.TrimSpace(expectedType))
	if t == "storagegateway" {
		return strings.Contains(a, ":storagegateway:") || strings.Contains(a, "storagegateway") || strings.Contains(a, "gateway")
	}
	if t == "virtualmachine" {
		return strings.Contains(a, "virtualmachine") || strings.Contains(a, "vmware") || strings.Contains(a, "backup-gateway")
	}
	return strings.Contains(a, t)
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "notfound") || strings.Contains(e, "resource not found") || strings.Contains(e, "resourcenotfoundexception")
}

func isAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "alreadyexists") || strings.Contains(e, "already exists") || strings.Contains(e, "alreadyexistsexception")
}

type backupPolicyDocument struct {
	Version   string        `json:"Version,omitempty"`
	Statement []interface{} `json:"Statement"`
}

type backupPolicyStatement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"`
	Action    interface{} `json:"Action"`
	Resource  string      `json:"Resource,omitempty"`
}

func addManualDeleteDenyPolicyStatement(policy string) (string, error) {
	required := backupPolicyStatement{
		Sid:       mb05DenyStatementSID,
		Effect:    "Deny",
		Principal: "*",
		Action: []string{
			"backup:DeleteRecoveryPoint",
			"backup:UpdateRecoveryPointLifecycle",
			"backup:PutBackupVaultAccessPolicy",
		},
		Resource: "*",
	}

	trimmed := strings.TrimSpace(policy)
	if trimmed == "" {
		doc := backupPolicyDocument{Version: "2012-10-17", Statement: []interface{}{required}}
		b, err := json.Marshal(doc)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	var generic map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &generic); err != nil {
		return "", err
	}
	stmtsRaw, ok := generic["Statement"]
	if !ok {
		generic["Statement"] = []interface{}{required}
	} else {
		switch s := stmtsRaw.(type) {
		case []interface{}:
			generic["Statement"] = append(s, required)
		case map[string]interface{}:
			generic["Statement"] = []interface{}{s, required}
		default:
			generic["Statement"] = []interface{}{required}
		}
	}
	if _, ok := generic["Version"]; !ok {
		generic["Version"] = "2012-10-17"
	}

	b, err := json.Marshal(generic)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func backupVaultPolicyDeniesManualDelete(policy string) bool {
	if strings.TrimSpace(policy) == "" {
		return false
	}
	var doc struct {
		Statement []backupPolicyStatement `json:"Statement"`
	}
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
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "deny") {
			continue
		}
		if !mb05PolicyPrincipalIsWildcard(stmt.Principal) {
			continue
		}
		for _, action := range mb05PolicyActions(stmt.Action) {
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

func mb05PolicyPrincipalIsWildcard(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return strings.TrimSpace(p) == "*"
	case map[string]interface{}:
		for _, v := range p {
			switch vv := v.(type) {
			case string:
				if strings.TrimSpace(vv) == "*" {
					return true
				}
			case []interface{}:
				for _, elem := range vv {
					if s, ok := elem.(string); ok && strings.TrimSpace(s) == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func mb05PolicyActions(action interface{}) []string {
	switch a := action.(type) {
	case string:
		return []string{a}
	case []interface{}:
		out := make([]string, 0, len(a))
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
