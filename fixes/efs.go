package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
)

// ── efs-automatic-backups-enabled ─────────────────────────────────────────────

type efsBackupFix struct{ clients *awsdata.Clients }

func (f *efsBackupFix) CheckID() string     { return "efs-automatic-backups-enabled" }
func (f *efsBackupFix) Description() string { return "Enable automatic backups on EFS file system" }
func (f *efsBackupFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *efsBackupFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *efsBackupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EFS.DescribeBackupPolicy(fctx.Ctx, &efs.DescribeBackupPolicyInput{
		FileSystemId: aws.String(resourceID),
	})
	if err == nil && out.BackupPolicy != nil && out.BackupPolicy.Status == efstypes.StatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "automatic backups already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable automatic backups on EFS file system " + resourceID}
		return base
	}

	_, err = f.clients.EFS.PutBackupPolicy(fctx.Ctx, &efs.PutBackupPolicyInput{
		FileSystemId: aws.String(resourceID),
		BackupPolicy: &efstypes.BackupPolicy{Status: efstypes.StatusEnabled},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put backup policy: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled automatic backups on EFS file system " + resourceID}
	base.Status = fix.FixApplied
	return base
}
