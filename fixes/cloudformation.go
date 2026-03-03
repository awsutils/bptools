package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

// ── cloudformation-termination-protection-check ───────────────────────────────

type cloudFormationTerminationProtectionFix struct{ clients *awsdata.Clients }

func (f *cloudFormationTerminationProtectionFix) CheckID() string {
	return "cloudformation-termination-protection-check"
}
func (f *cloudFormationTerminationProtectionFix) Description() string {
	return "Enable termination protection on CloudFormation stack"
}
func (f *cloudFormationTerminationProtectionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudFormationTerminationProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cloudFormationTerminationProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CloudFormation.DescribeStacks(fctx.Ctx, &cloudformation.DescribeStacksInput{
		StackName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe stack: " + err.Error()
		return base
	}
	if len(out.Stacks) > 0 && out.Stacks[0].EnableTerminationProtection != nil && *out.Stacks[0].EnableTerminationProtection {
		base.Status = fix.FixSkipped
		base.Message = "termination protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable termination protection on CloudFormation stack " + resourceID}
		return base
	}

	_, err = f.clients.CloudFormation.UpdateTerminationProtection(fctx.Ctx, &cloudformation.UpdateTerminationProtectionInput{
		StackName:                   aws.String(resourceID),
		EnableTerminationProtection: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update termination protection: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled termination protection on CloudFormation stack " + resourceID}
	base.Status = fix.FixApplied
	return base
}
