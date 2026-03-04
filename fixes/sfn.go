package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

// ── step-functions-state-machine-logging-enabled ──────────────────────────────

type sfnLoggingFix struct{ clients *awsdata.Clients }

func (f *sfnLoggingFix) CheckID() string {
	return "step-functions-state-machine-logging-enabled"
}
func (f *sfnLoggingFix) Description() string {
	return "Enable CloudWatch logging on Step Functions state machine"
}
func (f *sfnLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *sfnLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *sfnLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.SFN.DescribeStateMachine(fctx.Ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe state machine: " + err.Error()
		return base
	}

	// Idempotency check: logging already enabled with destinations
	if out.LoggingConfiguration != nil &&
		len(out.LoggingConfiguration.Destinations) > 0 &&
		out.LoggingConfiguration.Level != sfntypes.LogLevelOff {
		base.Status = fix.FixSkipped
		base.Message = "logging already enabled"
		return base
	}

	// Derive log group name from state machine name
	smName := ""
	if out.Name != nil {
		smName = *out.Name
	} else {
		// Parse name from ARN: arn:aws:states:region:account:stateMachine:name
		parts := strings.Split(resourceID, ":")
		if len(parts) >= 7 {
			smName = parts[6]
		} else {
			smName = resourceID
		}
	}

	// Derive region and account from ARN for log group ARN
	// ARN format: arn:aws:states:region:account:stateMachine:name
	arnParts := strings.Split(resourceID, ":")
	region, account := "", ""
	if len(arnParts) >= 6 {
		region = arnParts[3]
		account = arnParts[4]
	}

	logGroupName := "/aws/states/" + smName
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable ALL-level logging on state machine %s", smName),
		}
		return base
	}

	// Create log group (ignore AlreadyExistsException)
	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.SFN.UpdateStateMachine(fctx.Ctx, &sfn.UpdateStateMachineInput{
		StateMachineArn: aws.String(resourceID),
		RoleArn:         out.RoleArn,
		LoggingConfiguration: &sfntypes.LoggingConfiguration{
			Level:                sfntypes.LogLevelAll,
			IncludeExecutionData: false,
			Destinations: []sfntypes.LogDestination{
				{
					CloudWatchLogsLogGroup: &sfntypes.CloudWatchLogsLogGroup{
						LogGroupArn: aws.String(logGroupArn),
					},
				},
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update state machine: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("created log group %s", logGroupName),
		fmt.Sprintf("enabled ALL-level logging on state machine %s", smName),
	}
	base.Status = fix.FixApplied
	return base
}
