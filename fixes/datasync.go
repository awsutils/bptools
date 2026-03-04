package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
)

// ── datasync-task-logging-enabled ────────────────────────────────────────────

type dataSyncTaskLoggingFix struct{ clients *awsdata.Clients }

func (f *dataSyncTaskLoggingFix) CheckID() string { return "datasync-task-logging-enabled" }
func (f *dataSyncTaskLoggingFix) Description() string {
	return "Enable CloudWatch logging on DataSync task"
}
func (f *dataSyncTaskLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dataSyncTaskLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *dataSyncTaskLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DataSync.DescribeTask(fctx.Ctx, &datasync.DescribeTaskInput{
		TaskArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe task: " + err.Error()
		return base
	}
	if out.CloudWatchLogGroupArn != nil && *out.CloudWatchLogGroupArn != "" {
		base.Status = fix.FixSkipped
		base.Message = "CloudWatch logging already enabled"
		return base
	}

	// Derive region and account from task ARN
	// ARN format: arn:aws:datasync:region:account:task/task-xxxxx
	arnParts := strings.Split(resourceID, ":")
	region, account := "", ""
	if len(arnParts) >= 6 {
		region = arnParts[3]
		account = arnParts[4]
	}

	logGroupName := "/aws/datasync"
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable CloudWatch logging on DataSync task %s", resourceID),
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

	_, err = f.clients.DataSync.UpdateTask(fctx.Ctx, &datasync.UpdateTaskInput{
		TaskArn:              aws.String(resourceID),
		CloudWatchLogGroupArn: aws.String(logGroupArn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update task: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("ensured log group %s exists", logGroupName),
		fmt.Sprintf("enabled CloudWatch logging on DataSync task %s", resourceID),
	}
	base.Status = fix.FixApplied
	return base
}

// ── datasync-task-data-verification-enabled ───────────────────────────────────

type dataSyncTaskVerificationFix struct{ clients *awsdata.Clients }

func (f *dataSyncTaskVerificationFix) CheckID() string {
	return "datasync-task-data-verification-enabled"
}
func (f *dataSyncTaskVerificationFix) Description() string {
	return "Enable data verification on DataSync task"
}
func (f *dataSyncTaskVerificationFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dataSyncTaskVerificationFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *dataSyncTaskVerificationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DataSync.DescribeTask(fctx.Ctx, &datasync.DescribeTaskInput{
		TaskArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe task: " + err.Error()
		return base
	}
	if out.Options != nil && out.Options.VerifyMode != datasynctypes.VerifyModeNone && out.Options.VerifyMode != "" {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("data verification already enabled (mode: %s)", out.Options.VerifyMode)
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable ONLY_FILES_TRANSFERRED verification on DataSync task %s", resourceID)}
		return base
	}

	// Copy existing options and set VerifyMode
	opts := out.Options
	if opts == nil {
		opts = &datasynctypes.Options{}
	}
	opts.VerifyMode = datasynctypes.VerifyModeOnlyFilesTransferred

	_, err = f.clients.DataSync.UpdateTask(fctx.Ctx, &datasync.UpdateTaskInput{
		TaskArn: aws.String(resourceID),
		Options: opts,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update task: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled ONLY_FILES_TRANSFERRED verification on DataSync task %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── datasync-location-object-storage-using-https ─────────────────────────────

type dataSyncObjectStorageHTTPSFix struct{ clients *awsdata.Clients }

func (f *dataSyncObjectStorageHTTPSFix) CheckID() string {
	return "datasync-location-object-storage-using-https"
}
func (f *dataSyncObjectStorageHTTPSFix) Description() string {
	return "Enforce HTTPS protocol on DataSync object storage location"
}
func (f *dataSyncObjectStorageHTTPSFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dataSyncObjectStorageHTTPSFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *dataSyncObjectStorageHTTPSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DataSync.DescribeLocationObjectStorage(fctx.Ctx, &datasync.DescribeLocationObjectStorageInput{
		LocationArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe location: " + err.Error()
		return base
	}
	if out.ServerProtocol == datasynctypes.ObjectStorageServerProtocolHttps {
		base.Status = fix.FixSkipped
		base.Message = "HTTPS protocol already configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set HTTPS protocol on DataSync object storage location %s", resourceID)}
		return base
	}

	_, err = f.clients.DataSync.UpdateLocationObjectStorage(fctx.Ctx, &datasync.UpdateLocationObjectStorageInput{
		LocationArn:    aws.String(resourceID),
		ServerProtocol: datasynctypes.ObjectStorageServerProtocolHttps,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update location: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set HTTPS protocol on DataSync object storage location %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
