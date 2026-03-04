package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
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

// ── cloudwatch-alarm-action-enabled-check ─────────────────────────────────────

type cwAlarmActionEnabledFix struct{ clients *awsdata.Clients }

func (f *cwAlarmActionEnabledFix) CheckID() string {
	return "cloudwatch-alarm-action-enabled-check"
}
func (f *cwAlarmActionEnabledFix) Description() string {
	return "Enable actions on CloudWatch alarm"
}
func (f *cwAlarmActionEnabledFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cwAlarmActionEnabledFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cwAlarmActionEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Extract alarm name from ARN if needed
	// ARN format: arn:aws:cloudwatch:region:account:alarm:alarmName
	alarmName := resourceID
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.SplitN(resourceID, ":", 7)
		if len(parts) == 7 {
			alarmName = parts[6]
		}
	}

	out, err := f.clients.CloudWatch.DescribeAlarms(fctx.Ctx, &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []string{alarmName},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe alarm: " + err.Error()
		return base
	}
	if len(out.MetricAlarms) > 0 && out.MetricAlarms[0].ActionsEnabled != nil && *out.MetricAlarms[0].ActionsEnabled {
		base.Status = fix.FixSkipped
		base.Message = "alarm actions already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable actions on CloudWatch alarm %s", alarmName)}
		return base
	}

	_, err = f.clients.CloudWatch.EnableAlarmActions(fctx.Ctx, &cloudwatch.EnableAlarmActionsInput{
		AlarmNames: []string{alarmName},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable alarm actions: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled actions on CloudWatch alarm %s", alarmName)}
	base.Status = fix.FixApplied
	return base
}
