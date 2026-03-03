package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macie2types "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// ── securityhub-enabled ───────────────────────────────────────────────────────

type securityHubFix struct{ clients *awsdata.Clients }

func (f *securityHubFix) CheckID() string          { return "securityhub-enabled" }
func (f *securityHubFix) Description() string      { return "Enable AWS Security Hub" }
func (f *securityHubFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *securityHubFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *securityHubFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	_, err := f.clients.SecurityHub.DescribeHub(fctx.Ctx, &securityhub.DescribeHubInput{})
	if err == nil {
		base.Status = fix.FixSkipped
		base.Message = "Security Hub already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable AWS Security Hub"}
		return base
	}

	_, err = f.clients.SecurityHub.EnableSecurityHub(fctx.Ctx, &securityhub.EnableSecurityHubInput{
		EnableDefaultStandards: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable security hub: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled AWS Security Hub with default standards"}
	base.Status = fix.FixApplied
	return base
}

// ── macie-status-check ────────────────────────────────────────────────────────

type macieFix struct{ clients *awsdata.Clients }

func (f *macieFix) CheckID() string          { return "macie-status-check" }
func (f *macieFix) Description() string      { return "Enable Amazon Macie" }
func (f *macieFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *macieFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *macieFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	sess, err := f.clients.Macie2.GetMacieSession(fctx.Ctx, &macie2.GetMacieSessionInput{})
	if err == nil && sess.Status == macie2types.MacieStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "Macie already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable Amazon Macie"}
		return base
	}

	if err != nil {
		// Macie has never been enabled — enable it fresh.
		_, err = f.clients.Macie2.EnableMacie(fctx.Ctx, &macie2.EnableMacieInput{})
	} else {
		// Macie exists but is paused — resume it.
		_, err = f.clients.Macie2.UpdateMacieSession(fctx.Ctx, &macie2.UpdateMacieSessionInput{
			Status: macie2types.MacieStatusEnabled,
		})
	}
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable macie: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled Amazon Macie"}
	base.Status = fix.FixApplied
	return base
}
