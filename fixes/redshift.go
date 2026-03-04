package fixes

import (
	"context"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"
	"bptools/fix/pool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ── redshift-cluster-maintenancesettings-check ────────────────────────────────

type redshiftVersionUpgradeFix struct{ clients *awsdata.Clients }

func (f *redshiftVersionUpgradeFix) CheckID() string {
	return "redshift-cluster-maintenancesettings-check"
}
func (f *redshiftVersionUpgradeFix) Description() string {
	return "Enable automatic version upgrades on Redshift cluster"
}
func (f *redshiftVersionUpgradeFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftVersionUpgradeFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *redshiftVersionUpgradeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Redshift.DescribeClusters(fctx.Ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) > 0 && out.Clusters[0].AllowVersionUpgrade != nil && *out.Clusters[0].AllowVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "allow version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable AllowVersionUpgrade on Redshift cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Redshift.ModifyCluster(fctx.Ctx, &redshift.ModifyClusterInput{
		ClusterIdentifier:   aws.String(resourceID),
		AllowVersionUpgrade: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled AllowVersionUpgrade on Redshift cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-enhanced-vpc-routing-enabled ─────────────────────────────────────

type redshiftEnhancedVPCRoutingFix struct{ clients *awsdata.Clients }

func (f *redshiftEnhancedVPCRoutingFix) CheckID() string {
	return "redshift-enhanced-vpc-routing-enabled"
}
func (f *redshiftEnhancedVPCRoutingFix) Description() string {
	return "Enable enhanced VPC routing on Redshift cluster"
}
func (f *redshiftEnhancedVPCRoutingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftEnhancedVPCRoutingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *redshiftEnhancedVPCRoutingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Redshift.DescribeClusters(fctx.Ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) > 0 && out.Clusters[0].EnhancedVpcRouting != nil && *out.Clusters[0].EnhancedVpcRouting {
		base.Status = fix.FixSkipped
		base.Message = "enhanced VPC routing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable enhanced VPC routing on Redshift cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Redshift.ModifyCluster(fctx.Ctx, &redshift.ModifyClusterInput{
		ClusterIdentifier:  aws.String(resourceID),
		EnhancedVpcRouting: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled enhanced VPC routing on Redshift cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-backup-enabled ───────────────────────────────────────────────────

type redshiftBackupFix struct{ clients *awsdata.Clients }

func (f *redshiftBackupFix) CheckID() string     { return "redshift-backup-enabled" }
func (f *redshiftBackupFix) Description() string { return "Enable automated snapshots on Redshift cluster" }
func (f *redshiftBackupFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftBackupFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *redshiftBackupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Redshift.DescribeClusters(fctx.Ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) > 0 && out.Clusters[0].AutomatedSnapshotRetentionPeriod != nil && *out.Clusters[0].AutomatedSnapshotRetentionPeriod > 0 {
		base.Status = fix.FixSkipped
		base.Message = "automated snapshot retention already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set automated snapshot retention to 7 days on Redshift cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Redshift.ModifyCluster(fctx.Ctx, &redshift.ModifyClusterInput{
		ClusterIdentifier:                aws.String(resourceID),
		AutomatedSnapshotRetentionPeriod: aws.Int32(7),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set automated snapshot retention to 7 days on Redshift cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-serverless-publish-logs-to-cloudwatch ───────────────────────────

type redshiftServerlessLogsFix struct{ clients *awsdata.Clients }

func (f *redshiftServerlessLogsFix) CheckID() string {
	return "redshift-serverless-publish-logs-to-cloudwatch"
}
func (f *redshiftServerlessLogsFix) Description() string {
	return "Enable CloudWatch log exports on Redshift Serverless namespace"
}
func (f *redshiftServerlessLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftServerlessLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *redshiftServerlessLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RedshiftServerless.GetNamespace(fctx.Ctx, &redshiftserverless.GetNamespaceInput{
		NamespaceName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get namespace: " + err.Error()
		return base
	}
	if out.Namespace != nil {
		required := map[string]bool{"connectionlog": false, "userlog": false}
		for _, exp := range out.Namespace.LogExports {
			name := strings.ToLower(string(exp))
			if _, ok := required[name]; ok {
				required[name] = true
			}
		}
		allPresent := true
		for _, ok := range required {
			if !ok {
				allPresent = false
				break
			}
		}
		if allPresent {
			base.Status = fix.FixSkipped
			base.Message = "required log exports already configured"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable connectionlog and userlog exports on Redshift Serverless namespace " + resourceID}
		return base
	}

	_, err = f.clients.RedshiftServerless.UpdateNamespace(fctx.Ctx, &redshiftserverless.UpdateNamespaceInput{
		NamespaceName: aws.String(resourceID),
		LogExports:    []rsstypes.LogExport{rsstypes.LogExportConnectionLog, rsstypes.LogExportUserLog},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update namespace: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled connectionlog and userlog exports on Redshift Serverless namespace " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-serverless-workgroup-routes-within-vpc ──────────────────────────

type redshiftServerlessEnhancedVPCFix struct{ clients *awsdata.Clients }

func (f *redshiftServerlessEnhancedVPCFix) CheckID() string {
	return "redshift-serverless-workgroup-routes-within-vpc"
}
func (f *redshiftServerlessEnhancedVPCFix) Description() string {
	return "Enable enhanced VPC routing on Redshift Serverless workgroup"
}
func (f *redshiftServerlessEnhancedVPCFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftServerlessEnhancedVPCFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *redshiftServerlessEnhancedVPCFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RedshiftServerless.GetWorkgroup(fctx.Ctx, &redshiftserverless.GetWorkgroupInput{
		WorkgroupName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get workgroup: " + err.Error()
		return base
	}
	if out.Workgroup != nil && out.Workgroup.EnhancedVpcRouting != nil && *out.Workgroup.EnhancedVpcRouting {
		base.Status = fix.FixSkipped
		base.Message = "enhanced VPC routing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable enhanced VPC routing on Redshift Serverless workgroup " + resourceID}
		return base
	}

	_, err = f.clients.RedshiftServerless.UpdateWorkgroup(fctx.Ctx, &redshiftserverless.UpdateWorkgroupInput{
		WorkgroupName:      aws.String(resourceID),
		EnhancedVpcRouting: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update workgroup: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled enhanced VPC routing on Redshift Serverless workgroup " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-cluster-public-access-check ─────────────────────────────────────

type redshiftPublicAccessFix struct{ clients *awsdata.Clients }

func (f *redshiftPublicAccessFix) CheckID() string {
	return "redshift-cluster-public-access-check"
}
func (f *redshiftPublicAccessFix) Description() string {
	return "Disable public accessibility on Redshift cluster"
}
func (f *redshiftPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *redshiftPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *redshiftPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Redshift.DescribeClusters(fctx.Ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Redshift cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) > 0 && out.Clusters[0].PubliclyAccessible != nil && !*out.Clusters[0].PubliclyAccessible {
		base.Status = fix.FixSkipped
		base.Message = "cluster is already not publicly accessible"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public accessibility on Redshift cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Redshift.ModifyCluster(fctx.Ctx, &redshift.ModifyClusterInput{
		ClusterIdentifier: aws.String(resourceID),
		PubliclyAccessible: aws.Bool(false),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify Redshift cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled public accessibility on Redshift cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-serverless-workgroup-no-public-access ────────────────────────────

type redshiftServerlessPublicAccessFix struct{ clients *awsdata.Clients }

func (f *redshiftServerlessPublicAccessFix) CheckID() string {
	return "redshift-serverless-workgroup-no-public-access"
}
func (f *redshiftServerlessPublicAccessFix) Description() string {
	return "Disable public accessibility on Redshift Serverless workgroup"
}
func (f *redshiftServerlessPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *redshiftServerlessPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *redshiftServerlessPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RedshiftServerless.GetWorkgroup(fctx.Ctx, &redshiftserverless.GetWorkgroupInput{
		WorkgroupName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get Redshift Serverless workgroup: " + err.Error()
		return base
	}
	if out.Workgroup != nil && out.Workgroup.PubliclyAccessible != nil && !*out.Workgroup.PubliclyAccessible {
		base.Status = fix.FixSkipped
		base.Message = "workgroup is already not publicly accessible"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public accessibility on Redshift Serverless workgroup %s", resourceID)}
		return base
	}

	_, err = f.clients.RedshiftServerless.UpdateWorkgroup(fctx.Ctx, &redshiftserverless.UpdateWorkgroupInput{
		WorkgroupName:    aws.String(resourceID),
		PubliclyAccessible: aws.Bool(false),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update workgroup: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled public accessibility on Redshift Serverless workgroup %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── redshift-audit-logging-enabled ───────────────────────────────────────────

type redshiftAuditLoggingFix struct {
	clients *awsdata.Clients
	pool    *pool.S3BucketPool
}

func newRedshiftAuditLoggingFix(clients *awsdata.Clients, p *pool.S3BucketPool) *redshiftAuditLoggingFix {
	return &redshiftAuditLoggingFix{clients: clients, pool: p}
}

func (f *redshiftAuditLoggingFix) CheckID() string { return "redshift-audit-logging-enabled" }
func (f *redshiftAuditLoggingFix) Description() string {
	return "Enable audit logging on Redshift cluster"
}
func (f *redshiftAuditLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *redshiftAuditLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *redshiftAuditLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Redshift.DescribeClusters(fctx.Ctx, &redshift.DescribeClustersInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) == 0 {
		base.Status = fix.FixFailed
		base.Message = "cluster not found"
		return base
	}

	logOut, err := f.clients.Redshift.DescribeLoggingStatus(fctx.Ctx, &redshift.DescribeLoggingStatusInput{
		ClusterIdentifier: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe logging status: " + err.Error()
		return base
	}
	if logOut.LoggingEnabled != nil && *logOut.LoggingEnabled {
		base.Status = fix.FixSkipped
		base.Message = "audit logging already enabled"
		return base
	}

	region := f.clients.CloudWatchLogs.Options().Region
	bucketName, steps, err := f.pool.Ensure(fctx.Ctx, pool.S3BucketSpec{
		Purpose:        "redshift-audit",
		Region:         region,
		BucketPrefix:   "logs-",
		BucketPolicyFn: redshiftAuditLogsBucketPolicy,
	}, fctx.DryRun)
	base.Steps = append(base.Steps, steps...)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure S3 bucket: " + err.Error()
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = append(base.Steps,
			fmt.Sprintf("would enable audit logging on Redshift cluster %s → s3://%s/%s/", resourceID, bucketName, resourceID),
		)
		return base
	}

	_, err = f.clients.Redshift.EnableLogging(fctx.Ctx, &redshift.EnableLoggingInput{
		ClusterIdentifier: aws.String(resourceID),
		BucketName:        aws.String(bucketName),
		S3KeyPrefix:       aws.String(resourceID + "/"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable logging: " + err.Error()
		return base
	}
	base.Steps = append(base.Steps,
		fmt.Sprintf("enabled audit logging on Redshift cluster %s → s3://%s/%s/", resourceID, bucketName, resourceID),
	)
	base.Status = fix.FixApplied
	return base
}

func redshiftAuditLogsBucketPolicy(ctx context.Context, s3Client *s3.Client, bucketName string) error {
	policy := fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[`+
			`{"Sid":"RedshiftAuditLogsWrite","Effect":"Allow",`+
			`"Principal":{"Service":"redshift.amazonaws.com"},`+
			`"Action":["s3:PutObject","s3:GetBucketAcl"],`+
			`"Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`,
		bucketName, bucketName,
	)
	_, err := s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(policy),
	})
	return err
}

// Suppress unused import warning
var _ = strings.HasPrefix
