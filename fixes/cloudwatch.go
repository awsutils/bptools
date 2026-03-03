package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// ── cw-loggroup-retention-period-check ───────────────────────────────────────

type cwLogGroupRetentionFix struct{ clients *awsdata.Clients }

func (f *cwLogGroupRetentionFix) CheckID() string {
	return "cw-loggroup-retention-period-check"
}
func (f *cwLogGroupRetentionFix) Description() string {
	return "Set CloudWatch log group retention to at least 365 days"
}
func (f *cwLogGroupRetentionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cwLogGroupRetentionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cwLogGroupRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudWatchLogs.DescribeLogGroups(fctx.Ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe log groups: " + err.Error()
		return base
	}
	for _, g := range out.LogGroups {
		if g.LogGroupName != nil && *g.LogGroupName == resourceID {
			// nil means never-expire — already compliant
			if g.RetentionInDays == nil || *g.RetentionInDays >= 365 {
				base.Status = fix.FixSkipped
				base.Message = fmt.Sprintf("log group retention already >= 365 days")
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set retention to 365 days on log group %s", resourceID)}
		return base
	}

	_, err = f.clients.CloudWatchLogs.PutRetentionPolicy(fctx.Ctx, &cloudwatchlogs.PutRetentionPolicyInput{
		LogGroupName:    aws.String(resourceID),
		RetentionInDays: aws.Int32(365),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put retention policy: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set retention to 365 days on log group %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
