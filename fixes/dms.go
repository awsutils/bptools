package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

// ── dms-auto-minor-version-upgrade-check ──────────────────────────────────────

type dmsAutoMinorVersionFix struct{ clients *awsdata.Clients }

func (f *dmsAutoMinorVersionFix) CheckID() string {
	return "dms-auto-minor-version-upgrade-check"
}
func (f *dmsAutoMinorVersionFix) Description() string {
	return "Enable auto minor version upgrade on DMS replication instance"
}
func (f *dmsAutoMinorVersionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dmsAutoMinorVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *dmsAutoMinorVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DMS.DescribeReplicationInstances(fctx.Ctx, &databasemigrationservice.DescribeReplicationInstancesInput{
		Filters: []dmstypes.Filter{
			{Name: aws.String("replication-instance-arn"), Values: []string{resourceID}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe replication instances: " + err.Error()
		return base
	}
	if len(out.ReplicationInstances) > 0 && out.ReplicationInstances[0].AutoMinorVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "auto minor version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable auto minor version upgrade on DMS replication instance " + resourceID}
		return base
	}

	_, err = f.clients.DMS.ModifyReplicationInstance(fctx.Ctx, &databasemigrationservice.ModifyReplicationInstanceInput{
		ReplicationInstanceArn:  aws.String(resourceID),
		AutoMinorVersionUpgrade: aws.Bool(true),
		ApplyImmediately:        true,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify replication instance: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled auto minor version upgrade on DMS replication instance " + resourceID}
	base.Status = fix.FixApplied
	return base
}
