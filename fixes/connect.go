package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"
)

// ── connect-instance-logging-enabled ─────────────────────────────────────────

type connectInstanceLoggingFix struct{ clients *awsdata.Clients }

func (f *connectInstanceLoggingFix) CheckID() string { return "connect-instance-logging-enabled" }
func (f *connectInstanceLoggingFix) Description() string {
	return "Enable contact flow logs on Amazon Connect instance"
}
func (f *connectInstanceLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *connectInstanceLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *connectInstanceLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Connect.DescribeInstanceAttribute(fctx.Ctx, &connect.DescribeInstanceAttributeInput{
		InstanceId:    aws.String(resourceID),
		AttributeType: connecttypes.InstanceAttributeTypeContactflowLogs,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe instance attribute: " + err.Error()
		return base
	}
	if out.Attribute != nil && out.Attribute.Value != nil && *out.Attribute.Value == "true" {
		base.Status = fix.FixSkipped
		base.Message = "contact flow logging already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable contact flow logging on Connect instance " + resourceID}
		return base
	}

	_, err = f.clients.Connect.UpdateInstanceAttribute(fctx.Ctx, &connect.UpdateInstanceAttributeInput{
		InstanceId:    aws.String(resourceID),
		AttributeType: connecttypes.InstanceAttributeTypeContactflowLogs,
		Value:         aws.String("true"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update instance attribute: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled contact flow logging on Connect instance " + resourceID}
	base.Status = fix.FixApplied
	return base
}
