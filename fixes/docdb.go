package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
)

// ── docdb-cluster-deletion-protection-enabled ─────────────────────────────────

type docDBDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *docDBDeletionProtectionFix) CheckID() string {
	return "docdb-cluster-deletion-protection-enabled"
}
func (f *docDBDeletionProtectionFix) Description() string {
	return "Enable deletion protection on DocumentDB cluster"
}
func (f *docDBDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *docDBDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *docDBDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DocDB.DescribeDBClusters(fctx.Ctx, &docdb.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DocumentDB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].DeletionProtection != nil && *out.DBClusters[0].DeletionProtection {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable deletion protection on DocumentDB cluster " + resourceID}
		return base
	}

	_, err = f.clients.DocDB.ModifyDBCluster(fctx.Ctx, &docdb.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		DeletionProtection:  aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DocumentDB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled deletion protection on DocumentDB cluster " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── docdb-cluster-audit-logging-enabled ──────────────────────────────────────

type docDBClusterAuditLoggingFix struct{ clients *awsdata.Clients }

func (f *docDBClusterAuditLoggingFix) CheckID() string {
	return "docdb-cluster-audit-logging-enabled"
}
func (f *docDBClusterAuditLoggingFix) Description() string {
	return "Enable audit log exports to CloudWatch on DocumentDB cluster"
}
func (f *docDBClusterAuditLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *docDBClusterAuditLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *docDBClusterAuditLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DocDB.DescribeDBClusters(fctx.Ctx, &docdb.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DocumentDB cluster: " + err.Error()
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
		base.Steps = []string{fmt.Sprintf("would enable audit log export on DocumentDB cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.DocDB.ModifyDBCluster(fctx.Ctx, &docdb.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &docdbtypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"audit"},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DocumentDB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled audit log export on DocumentDB cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── docdb-cluster-backup-retention-check ─────────────────────────────────────

type docDBClusterBackupRetentionFix struct{ clients *awsdata.Clients }

func (f *docDBClusterBackupRetentionFix) CheckID() string {
	return "docdb-cluster-backup-retention-check"
}
func (f *docDBClusterBackupRetentionFix) Description() string {
	return "Set DocumentDB cluster backup retention to at least 7 days"
}
func (f *docDBClusterBackupRetentionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *docDBClusterBackupRetentionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *docDBClusterBackupRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DocDB.DescribeDBClusters(fctx.Ctx, &docdb.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DocumentDB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].BackupRetentionPeriod != nil && *out.DBClusters[0].BackupRetentionPeriod >= 7 {
		base.Status = fix.FixSkipped
		base.Message = "backup retention already >= 7 days"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set BackupRetentionPeriod=7 on DocumentDB cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.DocDB.ModifyDBCluster(fctx.Ctx, &docdb.ModifyDBClusterInput{
		DBClusterIdentifier:   aws.String(resourceID),
		BackupRetentionPeriod: aws.Int32(7),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DocumentDB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set BackupRetentionPeriod=7 on DocumentDB cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── docdb-cluster-snapshot-public-prohibited ──────────────────────────────────

type docDBSnapshotPublicFix struct{ clients *awsdata.Clients }

func (f *docDBSnapshotPublicFix) CheckID() string {
	return "docdb-cluster-snapshot-public-prohibited"
}
func (f *docDBSnapshotPublicFix) Description() string {
	return "Remove public restore access from DocumentDB cluster snapshot"
}
func (f *docDBSnapshotPublicFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *docDBSnapshotPublicFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *docDBSnapshotPublicFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Extract snapshot identifier from ARN: arn:aws:rds:...:cluster-snapshot:snapshot-id
	snapshotID := resourceID
	if idx := strings.LastIndex(resourceID, ":"); idx >= 0 {
		snapshotID = resourceID[idx+1:]
	}

	attrOut, err := f.clients.DocDB.DescribeDBClusterSnapshotAttributes(fctx.Ctx,
		&docdb.DescribeDBClusterSnapshotAttributesInput{
			DBClusterSnapshotIdentifier: aws.String(snapshotID),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe snapshot attributes: " + err.Error()
		return base
	}

	isPublic := false
	if attrOut.DBClusterSnapshotAttributesResult != nil {
		for _, a := range attrOut.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
			if aws.ToString(a.AttributeName) == "restore" {
				for _, v := range a.AttributeValues {
					if v == "all" {
						isPublic = true
						break
					}
				}
			}
		}
	}
	if !isPublic {
		base.Status = fix.FixSkipped
		base.Message = "snapshot is already private"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public restore access from DocumentDB snapshot %s", snapshotID)}
		return base
	}

	_, err = f.clients.DocDB.ModifyDBClusterSnapshotAttribute(fctx.Ctx,
		&docdb.ModifyDBClusterSnapshotAttributeInput{
			DBClusterSnapshotIdentifier: aws.String(snapshotID),
			AttributeName:               aws.String("restore"),
			ValuesToRemove:              []string{"all"},
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify snapshot attribute: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public restore access from DocumentDB snapshot %s", snapshotID)}
	base.Status = fix.FixApplied
	return base
}

// ── docdb-cluster-encrypted-in-transit ───────────────────────────────────────

type docDBTLSFix struct{ clients *awsdata.Clients }

func (f *docDBTLSFix) CheckID() string { return "docdb-cluster-encrypted-in-transit" }
func (f *docDBTLSFix) Description() string {
	return "Enable TLS encryption in transit on DocumentDB cluster"
}
func (f *docDBTLSFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *docDBTLSFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *docDBTLSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	clOut, err := f.clients.DocDB.DescribeDBClusters(fctx.Ctx, &docdb.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(clOut.DBClusters) == 0 {
		base.Status = fix.FixFailed
		base.Message = "cluster not found"
		return base
	}
	cluster := clOut.DBClusters[0]

	pgName := ""
	if cluster.DBClusterParameterGroup != nil {
		pgName = *cluster.DBClusterParameterGroup
	}
	if pgName == "" {
		base.Status = fix.FixFailed
		base.Message = "cluster has no parameter group"
		return base
	}

	// Check if TLS is already enabled in the parameter group
	pgOut, err := f.clients.DocDB.DescribeDBClusterParameters(fctx.Ctx,
		&docdb.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: aws.String(pgName),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster parameters: " + err.Error()
		return base
	}
	for _, p := range pgOut.Parameters {
		if aws.ToString(p.ParameterName) == "tls" && aws.ToString(p.ParameterValue) == "enabled" {
			base.Status = fix.FixSkipped
			base.Message = "TLS already enabled on parameter group " + pgName
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would set tls=enabled on parameter group %s", pgName),
			fmt.Sprintf("would apply parameter group %s to DocumentDB cluster %s", pgName, resourceID),
		}
		return base
	}

	_, err = f.clients.DocDB.ModifyDBClusterParameterGroup(fctx.Ctx,
		&docdb.ModifyDBClusterParameterGroupInput{
			DBClusterParameterGroupName: aws.String(pgName),
			Parameters: []docdbtypes.Parameter{
				{
					ParameterName:  aws.String("tls"),
					ParameterValue: aws.String("enabled"),
					ApplyMethod:    docdbtypes.ApplyMethodPendingReboot,
				},
			},
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cluster parameter group: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set tls=enabled on parameter group %s for DocumentDB cluster %s", pgName, resourceID)}
	base.Status = fix.FixApplied
	return base
}
