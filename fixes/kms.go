package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// ── cmk-backing-key-rotation-enabled ─────────────────────────────────────────

type kmsKeyRotationFix struct{ clients *awsdata.Clients }

func (f *kmsKeyRotationFix) CheckID() string     { return "cmk-backing-key-rotation-enabled" }
func (f *kmsKeyRotationFix) Description() string { return "Enable automatic KMS key rotation" }
func (f *kmsKeyRotationFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *kmsKeyRotationFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *kmsKeyRotationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.KMS.GetKeyRotationStatus(fctx.Ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get key rotation status: " + err.Error()
		return base
	}
	if out.KeyRotationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "key rotation already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable automatic rotation for KMS key " + resourceID}
		return base
	}

	_, err = f.clients.KMS.EnableKeyRotation(fctx.Ctx, &kms.EnableKeyRotationInput{
		KeyId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable key rotation: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled automatic rotation for KMS key " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── kms-cmk-not-scheduled-for-deletion ───────────────────────────────────────

type kmsCancelDeletionFix struct{ clients *awsdata.Clients }

func (f *kmsCancelDeletionFix) CheckID() string     { return "kms-cmk-not-scheduled-for-deletion" }
func (f *kmsCancelDeletionFix) Description() string { return "Cancel pending KMS key deletion" }
func (f *kmsCancelDeletionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *kmsCancelDeletionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *kmsCancelDeletionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.KMS.DescribeKey(fctx.Ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe key: " + err.Error()
		return base
	}
	if out.KeyMetadata == nil || (string(out.KeyMetadata.KeyState) != "PendingDeletion" && string(out.KeyMetadata.KeyState) != "PendingReplicaDeletion") {
		base.Status = fix.FixSkipped
		base.Message = "key is not scheduled for deletion"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would cancel deletion for KMS key " + resourceID}
		return base
	}

	_, err = f.clients.KMS.CancelKeyDeletion(fctx.Ctx, &kms.CancelKeyDeletionInput{
		KeyId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "cancel key deletion: " + err.Error()
		return base
	}
	base.Steps = []string{"cancelled deletion for KMS key " + resourceID}
	base.Status = fix.FixApplied
	return base
}
