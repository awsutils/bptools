package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
)

// ── emr-block-public-access ───────────────────────────────────────────────────

type emrBlockPublicAccessFix struct{ clients *awsdata.Clients }

func (f *emrBlockPublicAccessFix) CheckID() string     { return "emr-block-public-access" }
func (f *emrBlockPublicAccessFix) Description() string { return "Enable EMR block public access" }
func (f *emrBlockPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *emrBlockPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *emrBlockPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EMR.GetBlockPublicAccessConfiguration(fctx.Ctx, &emr.GetBlockPublicAccessConfigurationInput{})
	alreadyOK := false
	if err == nil && out.BlockPublicAccessConfiguration != nil {
		cfg := out.BlockPublicAccessConfiguration
		alreadyOK = cfg.BlockPublicSecurityGroupRules != nil && *cfg.BlockPublicSecurityGroupRules &&
			emrPermittedRangesOnlySSH(cfg.PermittedPublicSecurityGroupRuleRanges)
	}
	if alreadyOK {
		base.Status = fix.FixSkipped
		base.Message = "EMR block public access already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable EMR block public access (allow SSH only on port 22)"}
		return base
	}

	_, err = f.clients.EMR.PutBlockPublicAccessConfiguration(fctx.Ctx, &emr.PutBlockPublicAccessConfigurationInput{
		BlockPublicAccessConfiguration: &emrtypes.BlockPublicAccessConfiguration{
			BlockPublicSecurityGroupRules: aws.Bool(true),
			PermittedPublicSecurityGroupRuleRanges: []emrtypes.PortRange{
				{MinRange: aws.Int32(22), MaxRange: aws.Int32(22)},
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put block public access configuration: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled EMR block public access (allow SSH only on port 22)"}
	base.Status = fix.FixApplied
	return base
}

// emrPermittedRangesOnlySSH returns true if the only permitted range is SSH (port 22).
func emrPermittedRangesOnlySSH(ranges []emrtypes.PortRange) bool {
	for _, r := range ranges {
		if r.MinRange == nil || r.MaxRange == nil {
			return false
		}
		if *r.MinRange != 22 || *r.MaxRange != 22 {
			return false
		}
	}
	return true
}
