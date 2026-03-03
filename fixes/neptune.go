package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
)

// neptune fix helpers — each fix re-describes the cluster for idempotency.

// ── neptune-cluster-deletion-protection-enabled ───────────────────────────────

type neptuneDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *neptuneDeletionProtectionFix) CheckID() string {
	return "neptune-cluster-deletion-protection-enabled"
}
func (f *neptuneDeletionProtectionFix) Description() string {
	return "Enable deletion protection on Neptune cluster"
}
func (f *neptuneDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *neptuneDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *neptuneDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Neptune.DescribeDBClusters(fctx.Ctx, &neptune.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Neptune cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].DeletionProtection != nil && *out.DBClusters[0].DeletionProtection {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable deletion protection on Neptune cluster " + resourceID}
		return base
	}

	_, err = f.clients.Neptune.ModifyDBCluster(fctx.Ctx, &neptune.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		DeletionProtection:  aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Neptune cluster: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled deletion protection on Neptune cluster " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── neptune-cluster-iam-database-authentication ───────────────────────────────

type neptuneIAMAuthFix struct{ clients *awsdata.Clients }

func (f *neptuneIAMAuthFix) CheckID() string {
	return "neptune-cluster-iam-database-authentication"
}
func (f *neptuneIAMAuthFix) Description() string {
	return "Enable IAM database authentication on Neptune cluster"
}
func (f *neptuneIAMAuthFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *neptuneIAMAuthFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *neptuneIAMAuthFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Neptune.DescribeDBClusters(fctx.Ctx, &neptune.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Neptune cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].IAMDatabaseAuthenticationEnabled != nil && *out.DBClusters[0].IAMDatabaseAuthenticationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "IAM database authentication already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable IAM database authentication on Neptune cluster " + resourceID}
		return base
	}

	_, err = f.clients.Neptune.ModifyDBCluster(fctx.Ctx, &neptune.ModifyDBClusterInput{
		DBClusterIdentifier:         aws.String(resourceID),
		EnableIAMDatabaseAuthentication: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Neptune cluster: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled IAM database authentication on Neptune cluster " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── neptune-cluster-copy-tags-to-snapshot-enabled ────────────────────────────

type neptuneCopyTagsToSnapshotFix struct{ clients *awsdata.Clients }

func (f *neptuneCopyTagsToSnapshotFix) CheckID() string {
	return "neptune-cluster-copy-tags-to-snapshot-enabled"
}
func (f *neptuneCopyTagsToSnapshotFix) Description() string {
	return "Enable copy tags to snapshots on Neptune cluster"
}
func (f *neptuneCopyTagsToSnapshotFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *neptuneCopyTagsToSnapshotFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *neptuneCopyTagsToSnapshotFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Neptune.DescribeDBClusters(fctx.Ctx, &neptune.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Neptune cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].CopyTagsToSnapshot != nil && *out.DBClusters[0].CopyTagsToSnapshot {
		base.Status = fix.FixSkipped
		base.Message = "copy tags to snapshot already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable copy tags to snapshots on Neptune cluster " + resourceID}
		return base
	}

	_, err = f.clients.Neptune.ModifyDBCluster(fctx.Ctx, &neptune.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CopyTagsToSnapshot:  aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Neptune cluster: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled copy tags to snapshots on Neptune cluster " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── neptune-cluster-backup-retention-check ───────────────────────────────────

type neptuneBackupRetentionFix struct{ clients *awsdata.Clients }

func (f *neptuneBackupRetentionFix) CheckID() string {
	return "neptune-cluster-backup-retention-check"
}
func (f *neptuneBackupRetentionFix) Description() string {
	return "Set Neptune cluster backup retention to at least 7 days"
}
func (f *neptuneBackupRetentionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *neptuneBackupRetentionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *neptuneBackupRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Neptune.DescribeDBClusters(fctx.Ctx, &neptune.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Neptune cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].BackupRetentionPeriod != nil && *out.DBClusters[0].BackupRetentionPeriod >= 7 {
		base.Status = fix.FixSkipped
		base.Message = "backup retention already >= 7 days"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set BackupRetentionPeriod=7 on Neptune cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Neptune.ModifyDBCluster(fctx.Ctx, &neptune.ModifyDBClusterInput{
		DBClusterIdentifier:   aws.String(resourceID),
		BackupRetentionPeriod: aws.Int32(7),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Neptune cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set BackupRetentionPeriod=7 on Neptune cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── neptune-cluster-cloudwatch-log-export-enabled ────────────────────────────

type neptuneCloudWatchLogsFix struct{ clients *awsdata.Clients }

func (f *neptuneCloudWatchLogsFix) CheckID() string {
	return "neptune-cluster-cloudwatch-log-export-enabled"
}
func (f *neptuneCloudWatchLogsFix) Description() string {
	return "Enable audit log exports to CloudWatch on Neptune cluster"
}
func (f *neptuneCloudWatchLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *neptuneCloudWatchLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *neptuneCloudWatchLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Neptune.DescribeDBClusters(fctx.Ctx, &neptune.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Neptune cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 {
		for _, v := range out.DBClusters[0].EnabledCloudwatchLogsExports {
			if strings.EqualFold(v, "audit") {
				base.Status = fix.FixSkipped
				base.Message = "audit log export already enabled"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable audit log export on Neptune cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Neptune.ModifyDBCluster(fctx.Ctx, &neptune.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &neptunetypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"audit"},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Neptune cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled audit log export on Neptune cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
