package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
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
