package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// ── iam-password-policy ───────────────────────────────────────────────────────

type iamPasswordPolicyFix struct{ clients *awsdata.Clients }

func (f *iamPasswordPolicyFix) CheckID() string     { return "iam-password-policy" }
func (f *iamPasswordPolicyFix) Description() string { return "Enforce IAM account password policy" }
func (f *iamPasswordPolicyFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *iamPasswordPolicyFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *iamPasswordPolicyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.IAM.GetAccountPasswordPolicy(fctx.Ctx, &iam.GetAccountPasswordPolicyInput{})
	alreadyOK := false
	if err == nil && out.PasswordPolicy != nil {
		pp := out.PasswordPolicy
		alreadyOK = pp.RequireUppercaseCharacters &&
			pp.RequireLowercaseCharacters &&
			pp.RequireNumbers &&
			pp.RequireSymbols &&
			pp.MinimumPasswordLength != nil && *pp.MinimumPasswordLength >= 14 &&
			pp.PasswordReusePrevention != nil && *pp.PasswordReusePrevention >= 24 &&
			pp.MaxPasswordAge != nil && *pp.MaxPasswordAge > 0 && *pp.MaxPasswordAge <= 90
	}
	if alreadyOK {
		base.Status = fix.FixSkipped
		base.Message = "password policy already meets requirements"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would update IAM account password policy (min length 14, uppercase, lowercase, numbers, symbols, 24 reuse prevention, 90 day max age)"}
		return base
	}

	_, err = f.clients.IAM.UpdateAccountPasswordPolicy(fctx.Ctx, &iam.UpdateAccountPasswordPolicyInput{
		MinimumPasswordLength:      aws.Int32(14),
		RequireUppercaseCharacters: true,
		RequireLowercaseCharacters: true,
		RequireNumbers:             true,
		RequireSymbols:             true,
		PasswordReusePrevention:    aws.Int32(24),
		MaxPasswordAge:             aws.Int32(90),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update account password policy: " + err.Error()
		return base
	}
	base.Steps = []string{"updated IAM account password policy (min length 14, uppercase, lowercase, numbers, symbols, 24 reuse prevention, 90 day max age)"}
	base.Status = fix.FixApplied
	return base
}

// ── iam-external-access-analyzer-enabled ─────────────────────────────────────

type iamAccessAnalyzerFix struct{ clients *awsdata.Clients }

func (f *iamAccessAnalyzerFix) CheckID() string {
	return "iam-external-access-analyzer-enabled"
}
func (f *iamAccessAnalyzerFix) Description() string {
	return "Create an IAM Access Analyzer for external access in this region"
}
func (f *iamAccessAnalyzerFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iamAccessAnalyzerFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *iamAccessAnalyzerFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.AccessAnalyzer.ListAnalyzers(fctx.Ctx, &accessanalyzer.ListAnalyzersInput{
		Type: accessanalyzertypes.TypeAccount,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list access analyzers: " + err.Error()
		return base
	}
	for _, a := range out.Analyzers {
		if a.Status == accessanalyzertypes.AnalyzerStatusActive {
			base.Status = fix.FixSkipped
			base.Message = "active external access analyzer already exists"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would create IAM Access Analyzer 'bptools-external-access-analyzer' (type: ACCOUNT)"}
		return base
	}

	_, err = f.clients.AccessAnalyzer.CreateAnalyzer(fctx.Ctx, &accessanalyzer.CreateAnalyzerInput{
		AnalyzerName: aws.String("bptools-external-access-analyzer"),
		Type:         accessanalyzertypes.TypeAccount,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create access analyzer: " + err.Error()
		return base
	}
	base.Steps = []string{"created IAM Access Analyzer 'bptools-external-access-analyzer' (type: ACCOUNT)"}
	base.Status = fix.FixApplied
	return base
}
