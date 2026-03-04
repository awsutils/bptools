package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const ssmPublicSharingSettingID = "/ssm/documents/console/public-sharing-permission"

// ── ssm-automation-block-public-sharing ───────────────────────────────────────

type ssmBlockPublicSharingFix struct{ clients *awsdata.Clients }

func (f *ssmBlockPublicSharingFix) CheckID() string {
	return "ssm-automation-block-public-sharing"
}
func (f *ssmBlockPublicSharingFix) Description() string {
	return "Block public sharing of SSM documents"
}
func (f *ssmBlockPublicSharingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ssmBlockPublicSharingFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ssmBlockPublicSharingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.SSM.GetServiceSetting(fctx.Ctx, &ssm.GetServiceSettingInput{
		SettingId: aws.String(ssmPublicSharingSettingID),
	})
	if err == nil && out.ServiceSetting != nil && out.ServiceSetting.SettingValue != nil &&
		*out.ServiceSetting.SettingValue == "true" {
		base.Status = fix.FixSkipped
		base.Message = "SSM public sharing already blocked"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would block public sharing of SSM documents"}
		return base
	}

	_, err = f.clients.SSM.UpdateServiceSetting(fctx.Ctx, &ssm.UpdateServiceSettingInput{
		SettingId:    aws.String(ssmPublicSharingSettingID),
		SettingValue: aws.String("true"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update SSM service setting: " + err.Error()
		return base
	}
	base.Steps = []string{"blocked public sharing of SSM documents"}
	base.Status = fix.FixApplied
	return base
}

// ── ssm-automation-logging-enabled ───────────────────────────────────────────

const (
	ssmAutomationLogDestSettingID = "/ssm/automation/customer-script-log-destination"
	ssmAutomationLogGroupSettingID = "/ssm/automation/customer-script-log-group-name"
)

type ssmAutomationLoggingFix struct{ clients *awsdata.Clients }

func (f *ssmAutomationLoggingFix) CheckID() string { return "ssm-automation-logging-enabled" }
func (f *ssmAutomationLoggingFix) Description() string {
	return "Enable CloudWatch logging for SSM Automation"
}
func (f *ssmAutomationLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ssmAutomationLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ssmAutomationLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Check current state
	destOut, _ := f.clients.SSM.GetServiceSetting(fctx.Ctx, &ssm.GetServiceSettingInput{
		SettingId: aws.String(ssmAutomationLogDestSettingID),
	})
	lgOut, _ := f.clients.SSM.GetServiceSetting(fctx.Ctx, &ssm.GetServiceSettingInput{
		SettingId: aws.String(ssmAutomationLogGroupSettingID),
	})

	destVal := ""
	lgVal := ""
	if destOut != nil && destOut.ServiceSetting != nil && destOut.ServiceSetting.SettingValue != nil {
		destVal = strings.TrimSpace(*destOut.ServiceSetting.SettingValue)
	}
	if lgOut != nil && lgOut.ServiceSetting != nil && lgOut.ServiceSetting.SettingValue != nil {
		lgVal = strings.TrimSpace(*lgOut.ServiceSetting.SettingValue)
	}

	if strings.EqualFold(destVal, "CloudWatch") && lgVal != "" {
		base.Status = fix.FixSkipped
		base.Message = "SSM Automation CloudWatch logging already configured"
		return base
	}

	logGroupName := "/aws/ssm/automation"

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			"would set SSM Automation log destination to CloudWatch",
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

	_, err := f.clients.SSM.UpdateServiceSetting(fctx.Ctx, &ssm.UpdateServiceSettingInput{
		SettingId:    aws.String(ssmAutomationLogDestSettingID),
		SettingValue: aws.String("CloudWatch"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set SSM automation log destination: " + err.Error()
		return base
	}

	_, err = f.clients.SSM.UpdateServiceSetting(fctx.Ctx, &ssm.UpdateServiceSettingInput{
		SettingId:    aws.String(ssmAutomationLogGroupSettingID),
		SettingValue: aws.String(logGroupName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set SSM automation log group: " + err.Error()
		return base
	}

	base.Steps = []string{
		fmt.Sprintf("ensured log group %s exists", logGroupName),
		"enabled SSM Automation CloudWatch logging",
	}
	base.Status = fix.FixApplied
	return base
}

// ── ssm-document-not-public ───────────────────────────────────────────────────

type ssmDocumentNotPublicFix struct{ clients *awsdata.Clients }

func (f *ssmDocumentNotPublicFix) CheckID() string { return "ssm-document-not-public" }
func (f *ssmDocumentNotPublicFix) Description() string {
	return "Remove public sharing from SSM document"
}
func (f *ssmDocumentNotPublicFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ssmDocumentNotPublicFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ssmDocumentNotPublicFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.SSM.DescribeDocumentPermission(fctx.Ctx, &ssm.DescribeDocumentPermissionInput{
		Name:           aws.String(resourceID),
		PermissionType: ssmtypes.DocumentPermissionTypeShare,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe document permission: " + err.Error()
		return base
	}

	isPublic := false
	for _, id := range out.AccountIds {
		if strings.EqualFold(id, "all") || strings.EqualFold(id, "*") {
			isPublic = true
			break
		}
	}
	if !isPublic {
		base.Status = fix.FixSkipped
		base.Message = "document is already not publicly shared"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public sharing from SSM document %s", resourceID)}
		return base
	}

	_, err = f.clients.SSM.ModifyDocumentPermission(fctx.Ctx, &ssm.ModifyDocumentPermissionInput{
		Name:               aws.String(resourceID),
		PermissionType:     ssmtypes.DocumentPermissionTypeShare,
		AccountIdsToRemove: []string{"all"},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify document permission: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public sharing from SSM document %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
