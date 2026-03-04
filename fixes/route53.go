package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ── route53-query-logging-enabled ─────────────────────────────────────────────

type route53QueryLoggingFix struct{ clients *awsdata.Clients }

func (f *route53QueryLoggingFix) CheckID() string { return "route53-query-logging-enabled" }
func (f *route53QueryLoggingFix) Description() string {
	return "Enable DNS query logging on Route 53 public hosted zone"
}
func (f *route53QueryLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *route53QueryLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *route53QueryLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Route 53 hosted zone IDs may be prefixed with "/hostedzone/"
	zoneID := strings.TrimPrefix(resourceID, "/hostedzone/")

	// Check if query logging is already configured
	listOut, err := f.clients.Route53.ListQueryLoggingConfigs(fctx.Ctx, &route53.ListQueryLoggingConfigsInput{
		HostedZoneId: aws.String(zoneID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list query logging configs: " + err.Error()
		return base
	}
	if len(listOut.QueryLoggingConfigs) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "query logging already enabled"
		return base
	}

	// Route 53 requires the log group to be in us-east-1
	callerOut, err := f.clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get caller identity: " + err.Error()
		return base
	}
	account := aws.ToString(callerOut.Account)

	logGroupName := "/aws/route53/" + zoneID
	logGroupArn := fmt.Sprintf("arn:aws:logs:us-east-1:%s:log-group:%s", account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s in us-east-1", logGroupName),
			fmt.Sprintf("would enable query logging on hosted zone %s", zoneID),
		}
		return base
	}

	// Create a CloudWatch Logs client in us-east-1 (Route53 requires this region)
	cwlOpts := f.clients.CloudWatchLogs.Options()
	cwlOpts.Region = "us-east-1"
	cwlUSEast1 := cloudwatchlogs.New(cwlOpts)

	_, cgErr := cwlUSEast1.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	// Route 53 requires a resource-based policy on the log group
	policyName := "route53-query-logging-" + zoneID
	policyDoc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"route53.amazonaws.com"},"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"%s:*","Condition":{"StringEquals":{"aws:SourceAccount":"%s"}}}]}`,
		logGroupArn, account)
	_, prErr := cwlUSEast1.PutResourcePolicy(fctx.Ctx, &cloudwatchlogs.PutResourcePolicyInput{
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(policyDoc),
	})
	if prErr != nil {
		base.Status = fix.FixFailed
		base.Message = "put log group resource policy: " + prErr.Error()
		return base
	}

	_, err = f.clients.Route53.CreateQueryLoggingConfig(fctx.Ctx, &route53.CreateQueryLoggingConfigInput{
		HostedZoneId:            aws.String(zoneID),
		CloudWatchLogsLogGroupArn: aws.String(logGroupArn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create query logging config: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("created log group %s in us-east-1", logGroupName),
		fmt.Sprintf("enabled DNS query logging on hosted zone %s", zoneID),
	}
	base.Status = fix.FixApplied
	return base
}
