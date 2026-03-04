package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// ── rds-instance-deletion-protection-enabled ────────────────────────────────

type rdsInstanceDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *rdsInstanceDeletionProtectionFix) CheckID() string {
	return "rds-instance-deletion-protection-enabled"
}
func (f *rdsInstanceDeletionProtectionFix) Description() string {
	return "Enable RDS instance deletion protection"
}
func (f *rdsInstanceDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsInstanceDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *rdsInstanceDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && out.DBInstances[0].DeletionProtection != nil && *out.DBInstances[0].DeletionProtection {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable deletion protection on RDS instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		DeletionProtection:   aws.Bool(true),
		ApplyImmediately:     aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled deletion protection on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-cluster-deletion-protection-enabled ─────────────────────────────────

type rdsClusterDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *rdsClusterDeletionProtectionFix) CheckID() string {
	return "rds-cluster-deletion-protection-enabled"
}
func (f *rdsClusterDeletionProtectionFix) Description() string {
	return "Enable RDS cluster deletion protection"
}
func (f *rdsClusterDeletionProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsClusterDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *rdsClusterDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].DeletionProtection != nil && *out.DBClusters[0].DeletionProtection {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable deletion protection on RDS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		DeletionProtection:  aws.Bool(true),
		ApplyImmediately:    aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled deletion protection on RDS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-multi-az-support ─────────────────────────────────────────────────────

type rdsMultiAZFix struct{ clients *awsdata.Clients }

func (f *rdsMultiAZFix) CheckID() string          { return "rds-multi-az-support" }
func (f *rdsMultiAZFix) Description() string      { return "Enable RDS Multi-AZ for high availability" }
func (f *rdsMultiAZFix) Impact() fix.ImpactType   { return fix.ImpactDown }
func (f *rdsMultiAZFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *rdsMultiAZFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && out.DBInstances[0].MultiAZ != nil && *out.DBInstances[0].MultiAZ {
		base.Status = fix.FixSkipped
		base.Message = "Multi-AZ already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable Multi-AZ on RDS instance %s (brief failover on next maintenance)", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		MultiAZ:              aws.Bool(true),
		ApplyImmediately:     aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled Multi-AZ on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-instance-iam-authentication-enabled ──────────────────────────────────

type rdsInstanceIAMAuthFix struct{ clients *awsdata.Clients }

func (f *rdsInstanceIAMAuthFix) CheckID() string          { return "rds-instance-iam-authentication-enabled" }
func (f *rdsInstanceIAMAuthFix) Description() string      { return "Enable RDS instance IAM database authentication" }
func (f *rdsInstanceIAMAuthFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsInstanceIAMAuthFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsInstanceIAMAuthFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && out.DBInstances[0].IAMDatabaseAuthenticationEnabled != nil && *out.DBInstances[0].IAMDatabaseAuthenticationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "IAM authentication already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable IAM database authentication on RDS instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier:            aws.String(resourceID),
		EnableIAMDatabaseAuthentication: aws.Bool(true),
		ApplyImmediately:                aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled IAM database authentication on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-cluster-iam-authentication-enabled ───────────────────────────────────

type rdsClusterIAMAuthFix struct{ clients *awsdata.Clients }

func (f *rdsClusterIAMAuthFix) CheckID() string          { return "rds-cluster-iam-authentication-enabled" }
func (f *rdsClusterIAMAuthFix) Description() string      { return "Enable RDS cluster IAM database authentication" }
func (f *rdsClusterIAMAuthFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsClusterIAMAuthFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsClusterIAMAuthFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].IAMDatabaseAuthenticationEnabled != nil && *out.DBClusters[0].IAMDatabaseAuthenticationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "IAM authentication already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable IAM database authentication on RDS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier:             aws.String(resourceID),
		EnableIAMDatabaseAuthentication: aws.Bool(true),
		ApplyImmediately:                aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled IAM database authentication on RDS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-automatic-minor-version-upgrade-enabled ──────────────────────────────

type rdsInstanceAutoMinorVersionFix struct{ clients *awsdata.Clients }

func (f *rdsInstanceAutoMinorVersionFix) CheckID() string { return "rds-automatic-minor-version-upgrade-enabled" }
func (f *rdsInstanceAutoMinorVersionFix) Description() string { return "Enable automatic minor version upgrades on RDS instance" }
func (f *rdsInstanceAutoMinorVersionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsInstanceAutoMinorVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *rdsInstanceAutoMinorVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && out.DBInstances[0].AutoMinorVersionUpgrade != nil && *out.DBInstances[0].AutoMinorVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "auto minor version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable auto minor version upgrade on RDS instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier:    aws.String(resourceID),
		AutoMinorVersionUpgrade: aws.Bool(true),
		ApplyImmediately:        aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled auto minor version upgrade on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-cluster-auto-minor-version-upgrade-enable ────────────────────────────

type rdsClusterAutoMinorVersionFix struct{ clients *awsdata.Clients }

func (f *rdsClusterAutoMinorVersionFix) CheckID() string { return "rds-cluster-auto-minor-version-upgrade-enable" }
func (f *rdsClusterAutoMinorVersionFix) Description() string { return "Enable automatic minor version upgrades on RDS cluster" }
func (f *rdsClusterAutoMinorVersionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsClusterAutoMinorVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *rdsClusterAutoMinorVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].AutoMinorVersionUpgrade != nil && *out.DBClusters[0].AutoMinorVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "auto minor version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable auto minor version upgrade on RDS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier:     aws.String(resourceID),
		AutoMinorVersionUpgrade: aws.Bool(true),
		ApplyImmediately:        aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled auto minor version upgrade on RDS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-logging-enabled ───────────────────────────────────────────────────────

type rdsInstanceLoggingFix struct{ clients *awsdata.Clients }

func (f *rdsInstanceLoggingFix) CheckID() string          { return "rds-logging-enabled" }
func (f *rdsInstanceLoggingFix) Description() string      { return "Enable CloudWatch log exports on RDS instance" }
func (f *rdsInstanceLoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsInstanceLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsInstanceLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) == 0 {
		base.Status = fix.FixFailed
		base.Message = "DB instance not found"
		return base
	}
	inst := out.DBInstances[0]
	required := rdsRequiredLogTypes(inst.Engine)
	if len(required) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "no specific log requirements for engine"
		return base
	}
	missing := rdssMissingLogs(required, inst.EnabledCloudwatchLogsExports)
	if len(missing) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "all required log types already exported"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable CloudWatch log exports %v on RDS instance %s", missing, resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: missing,
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled CloudWatch log exports %v on RDS instance %s", missing, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-aurora-mysql-audit-logging-enabled / aurora-mysql-cluster-audit-logging

// rdsAuroraMySQLClusterLoggingFix enables audit log export on Aurora MySQL clusters.
// Two check IDs map to the same fix.
type rdsAuroraMySQLClusterLoggingFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *rdsAuroraMySQLClusterLoggingFix) CheckID() string          { return f.checkID }
func (f *rdsAuroraMySQLClusterLoggingFix) Description() string      { return "Enable audit log exports on Aurora MySQL cluster" }
func (f *rdsAuroraMySQLClusterLoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *rdsAuroraMySQLClusterLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsAuroraMySQLClusterLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) == 0 {
		base.Status = fix.FixFailed
		base.Message = "DB cluster not found"
		return base
	}
	c := out.DBClusters[0]
	for _, v := range c.EnabledCloudwatchLogsExports {
		if strings.EqualFold(v, "audit") {
			base.Status = fix.FixSkipped
			base.Message = "audit log export already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable audit log export on Aurora MySQL cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"audit"},
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled audit log export on Aurora MySQL cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// rdsRequiredLogTypes returns the CloudWatch log types the check requires per engine.
func rdsRequiredLogTypes(engine *string) []string {
	if engine == nil {
		return nil
	}
	e := strings.ToLower(strings.TrimSpace(*engine))
	switch {
	case strings.Contains(e, "aurora-mysql"):
		return []string{"audit"}
	case strings.Contains(e, "aurora-postgresql"), strings.Contains(e, "postgres"):
		return []string{"postgresql"}
	case strings.Contains(e, "sqlserver"):
		return []string{"error"}
	case strings.Contains(e, "mysql"), strings.Contains(e, "mariadb"):
		return []string{"error", "general", "slowquery"}
	default:
		return nil
	}
}

// rdssMissingLogs returns required log types not present in the current exports.
func rdssMissingLogs(required, current []string) []string {
	have := make(map[string]bool, len(current))
	for _, v := range current {
		have[strings.ToLower(v)] = true
	}
	var missing []string
	for _, v := range required {
		if !have[strings.ToLower(v)] {
			missing = append(missing, v)
		}
	}
	return missing
}

// ── rds-instance-public-access-check ──────────────────────────────────────────

type rdsInstancePublicAccessFix struct{ clients *awsdata.Clients }

func (f *rdsInstancePublicAccessFix) CheckID() string {
	return "rds-instance-public-access-check"
}
func (f *rdsInstancePublicAccessFix) Description() string {
	return "Disable public accessibility on RDS instance"
}
func (f *rdsInstancePublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *rdsInstancePublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *rdsInstancePublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && (out.DBInstances[0].PubliclyAccessible == nil || !*out.DBInstances[0].PubliclyAccessible) {
		base.Status = fix.FixSkipped
		base.Message = "RDS instance is already not publicly accessible"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public accessibility on RDS instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		PubliclyAccessible:   aws.Bool(false),
		ApplyImmediately:     aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled public accessibility on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── db-instance-backup-enabled ────────────────────────────────────────────────

type rdsInstanceBackupFix struct{ clients *awsdata.Clients }

func (f *rdsInstanceBackupFix) CheckID() string     { return "db-instance-backup-enabled" }
func (f *rdsInstanceBackupFix) Description() string { return "Enable automated backups on RDS instance" }
func (f *rdsInstanceBackupFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsInstanceBackupFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsInstanceBackupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && out.DBInstances[0].BackupRetentionPeriod != nil && *out.DBInstances[0].BackupRetentionPeriod > 0 {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("backup retention already set to %d days", *out.DBInstances[0].BackupRetentionPeriod)
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable automated backups on RDS instance %s (retention 7 days)", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		BackupRetentionPeriod: aws.Int32(7),
		ApplyImmediately:     aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled automated backups on RDS instance %s (retention 7 days)", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-aurora-postgresql-logs-to-cloudwatch ──────────────────────────────────

type rdsAuroraPostgreSQLLoggingFix struct{ clients *awsdata.Clients }

func (f *rdsAuroraPostgreSQLLoggingFix) CheckID() string {
	return "rds-aurora-postgresql-logs-to-cloudwatch"
}
func (f *rdsAuroraPostgreSQLLoggingFix) Description() string {
	return "Enable postgresql log exports on Aurora PostgreSQL cluster"
}
func (f *rdsAuroraPostgreSQLLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsAuroraPostgreSQLLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsAuroraPostgreSQLLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) == 0 {
		base.Status = fix.FixFailed
		base.Message = "DB cluster not found"
		return base
	}
	c := out.DBClusters[0]
	for _, v := range c.EnabledCloudwatchLogsExports {
		if strings.EqualFold(v, "postgresql") {
			base.Status = fix.FixSkipped
			base.Message = "postgresql log export already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable postgresql log export on Aurora PostgreSQL cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"postgresql"},
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled postgresql log export on Aurora PostgreSQL cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-mysql-cluster-copy-tags-to-snapshot-check + rds-pgsql-cluster-copy-tags-to-snapshot-check

type rdsCopyTagsToSnapshotClusterFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *rdsCopyTagsToSnapshotClusterFix) CheckID() string     { return f.checkID }
func (f *rdsCopyTagsToSnapshotClusterFix) Description() string { return "Enable CopyTagsToSnapshot on RDS cluster" }
func (f *rdsCopyTagsToSnapshotClusterFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsCopyTagsToSnapshotClusterFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *rdsCopyTagsToSnapshotClusterFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].CopyTagsToSnapshot != nil && *out.DBClusters[0].CopyTagsToSnapshot {
		base.Status = fix.FixSkipped
		base.Message = "CopyTagsToSnapshot already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable CopyTagsToSnapshot on RDS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		CopyTagsToSnapshot:  aws.Bool(true),
		ApplyImmediately:    aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled CopyTagsToSnapshot on RDS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── mariadb-publish-logs-to-cloudwatch-logs ───────────────────────────────────

type mariadbCloudWatchLogsFix struct{ clients *awsdata.Clients }

func (f *mariadbCloudWatchLogsFix) CheckID() string {
	return "mariadb-publish-logs-to-cloudwatch-logs"
}
func (f *mariadbCloudWatchLogsFix) Description() string {
	return "Enable CloudWatch log exports on MariaDB instance"
}
func (f *mariadbCloudWatchLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *mariadbCloudWatchLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *mariadbCloudWatchLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) > 0 && len(out.DBInstances[0].EnabledCloudwatchLogsExports) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "CloudWatch log exports already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable CloudWatch log exports on MariaDB instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"general", "error", "slowquery"},
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled CloudWatch log exports (general, error, slowquery) on MariaDB instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── aurora-mysql-backtracking-enabled ────────────────────────────────────────

type auroraMySQLBacktrackingFix struct{ clients *awsdata.Clients }

func (f *auroraMySQLBacktrackingFix) CheckID() string {
	return "aurora-mysql-backtracking-enabled"
}
func (f *auroraMySQLBacktrackingFix) Description() string {
	return "Enable backtracking (24h window) on Aurora MySQL cluster"
}
func (f *auroraMySQLBacktrackingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *auroraMySQLBacktrackingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *auroraMySQLBacktrackingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBClusters(fctx.Ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB cluster: " + err.Error()
		return base
	}
	if len(out.DBClusters) > 0 && out.DBClusters[0].BacktrackWindow != nil && *out.DBClusters[0].BacktrackWindow > 0 {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("backtracking already enabled (window: %d s)", *out.DBClusters[0].BacktrackWindow)
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable backtracking (86400s) on Aurora MySQL cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBCluster(fctx.Ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(resourceID),
		BacktrackWindow:     aws.Int64(86400), // 24 hours
		ApplyImmediately:    aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled backtracking (86400s window) on Aurora MySQL cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-postgresql-logs-to-cloudwatch ────────────────────────────────────────

type rdsPostgreSQLLoggingFix struct{ clients *awsdata.Clients }

func (f *rdsPostgreSQLLoggingFix) CheckID() string {
	return "rds-postgresql-logs-to-cloudwatch"
}
func (f *rdsPostgreSQLLoggingFix) Description() string {
	return "Enable postgresql log exports on PostgreSQL RDS instance"
}
func (f *rdsPostgreSQLLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsPostgreSQLLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsPostgreSQLLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) == 0 {
		base.Status = fix.FixFailed
		base.Message = "DB instance not found"
		return base
	}
	inst := out.DBInstances[0]
	for _, v := range inst.EnabledCloudwatchLogsExports {
		if strings.EqualFold(v, "postgresql") {
			base.Status = fix.FixSkipped
			base.Message = "postgresql log export already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable postgresql log export on RDS instance %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: []string{"postgresql"},
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled postgresql log export on RDS instance %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-sql-server-logs-to-cloudwatch ────────────────────────────────────────

type rdsSQLServerLoggingFix struct{ clients *awsdata.Clients }

func (f *rdsSQLServerLoggingFix) CheckID() string {
	return "rds-sql-server-logs-to-cloudwatch"
}
func (f *rdsSQLServerLoggingFix) Description() string {
	return "Enable error and agent log exports on SQL Server RDS instance"
}
func (f *rdsSQLServerLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsSQLServerLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsSQLServerLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBInstances(fctx.Ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB instance: " + err.Error()
		return base
	}
	if len(out.DBInstances) == 0 {
		base.Status = fix.FixFailed
		base.Message = "DB instance not found"
		return base
	}
	inst := out.DBInstances[0]
	needed := []string{"error", "agent"}
	var toEnable []string
	for _, want := range needed {
		found := false
		for _, have := range inst.EnabledCloudwatchLogsExports {
			if strings.EqualFold(have, want) {
				found = true
				break
			}
		}
		if !found {
			toEnable = append(toEnable, want)
		}
	}
	if len(toEnable) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "SQL Server log exports already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable %v log exports on SQL Server RDS instance %s", toEnable, resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBInstance(fctx.Ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier: aws.String(resourceID),
		CloudwatchLogsExportConfiguration: &rdstypes.CloudwatchLogsExportConfiguration{
			EnableLogTypes: toEnable,
		},
		ApplyImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB instance: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled %v log exports on SQL Server RDS instance %s", toEnable, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-proxy-tls-encryption ──────────────────────────────────────────────────

type rdsProxyTLSFix struct{ clients *awsdata.Clients }

func (f *rdsProxyTLSFix) CheckID() string     { return "rds-proxy-tls-encryption" }
func (f *rdsProxyTLSFix) Description() string { return "Enforce TLS on RDS Proxy" }
func (f *rdsProxyTLSFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsProxyTLSFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rdsProxyTLSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RDS.DescribeDBProxies(fctx.Ctx, &rds.DescribeDBProxiesInput{
		DBProxyName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DB proxy: " + err.Error()
		return base
	}
	if len(out.DBProxies) > 0 && out.DBProxies[0].RequireTLS != nil && *out.DBProxies[0].RequireTLS {
		base.Status = fix.FixSkipped
		base.Message = "TLS already required"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable RequireTLS on RDS Proxy %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBProxy(fctx.Ctx, &rds.ModifyDBProxyInput{
		DBProxyName: aws.String(resourceID),
		RequireTLS:  aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DB proxy: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled RequireTLS on RDS Proxy %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── rds-snapshots-public-prohibited ──────────────────────────────────────────

type rdsSnapshotPublicFix struct{ clients *awsdata.Clients }

func (f *rdsSnapshotPublicFix) CheckID() string { return "rds-snapshots-public-prohibited" }
func (f *rdsSnapshotPublicFix) Description() string {
	return "Remove public restore access from RDS DB snapshot"
}
func (f *rdsSnapshotPublicFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rdsSnapshotPublicFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *rdsSnapshotPublicFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.RDS.DescribeDBSnapshotAttributes(fctx.Ctx,
		&rds.DescribeDBSnapshotAttributesInput{
			DBSnapshotIdentifier: aws.String(resourceID),
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe snapshot attributes: " + err.Error()
		return base
	}

	isPublic := false
	if attrOut.DBSnapshotAttributesResult != nil {
		for _, a := range attrOut.DBSnapshotAttributesResult.DBSnapshotAttributes {
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
		base.Steps = []string{fmt.Sprintf("would remove public restore access from RDS snapshot %s", resourceID)}
		return base
	}

	_, err = f.clients.RDS.ModifyDBSnapshotAttribute(fctx.Ctx,
		&rds.ModifyDBSnapshotAttributeInput{
			DBSnapshotIdentifier: aws.String(resourceID),
			AttributeName:        aws.String("restore"),
			ValuesToRemove:       []string{"all"},
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify snapshot attribute: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public restore access from RDS snapshot %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
