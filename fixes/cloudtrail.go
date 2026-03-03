package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// ── cloud-trail-log-file-validation-enabled ───────────────────────────────────

type cloudTrailLogFileValidationFix struct{ clients *awsdata.Clients }

func (f *cloudTrailLogFileValidationFix) CheckID() string {
	return "cloud-trail-log-file-validation-enabled"
}
func (f *cloudTrailLogFileValidationFix) Description() string {
	return "Enable CloudTrail log file validation"
}
func (f *cloudTrailLogFileValidationFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudTrailLogFileValidationFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudTrailLogFileValidationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudTrail.GetTrail(fctx.Ctx, &cloudtrail.GetTrailInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get trail: " + err.Error()
		return base
	}
	if out.Trail != nil && out.Trail.LogFileValidationEnabled != nil && *out.Trail.LogFileValidationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "log file validation already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable log file validation on CloudTrail trail %s", resourceID)}
		return base
	}

	_, err = f.clients.CloudTrail.UpdateTrail(fctx.Ctx, &cloudtrail.UpdateTrailInput{
		Name:                 aws.String(resourceID),
		EnableLogFileValidation: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update trail: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled log file validation on CloudTrail trail %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

type cloudTrailLoggingFix struct{ clients *awsdata.Clients }

func (f *cloudTrailLoggingFix) CheckID() string          { return "cloudtrail-enabled" }
func (f *cloudTrailLoggingFix) Description() string      { return "Start CloudTrail logging" }
func (f *cloudTrailLoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *cloudTrailLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cloudTrailLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Idempotency: re-check trail status.
	st, err := f.clients.CloudTrail.GetTrailStatus(fctx.Ctx, &cloudtrail.GetTrailStatusInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get trail status: " + err.Error()
		return base
	}
	if st.IsLogging != nil && *st.IsLogging {
		base.Status = fix.FixSkipped
		base.Message = "trail already logging"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would start logging on CloudTrail trail %s", resourceID)}
		return base
	}

	_, err = f.clients.CloudTrail.StartLogging(fctx.Ctx, &cloudtrail.StartLoggingInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start logging: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("started logging on CloudTrail trail %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
