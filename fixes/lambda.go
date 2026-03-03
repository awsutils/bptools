package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// ── lambda-function-xray-enabled ─────────────────────────────────────────────

type lambdaXRayFix struct{ clients *awsdata.Clients }

func (f *lambdaXRayFix) CheckID() string          { return "lambda-function-xray-enabled" }
func (f *lambdaXRayFix) Description() string      { return "Enable X-Ray active tracing on Lambda function" }
func (f *lambdaXRayFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *lambdaXRayFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *lambdaXRayFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Lambda.GetFunctionConfiguration(fctx.Ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get function configuration: " + err.Error()
		return base
	}
	if out.TracingConfig != nil && out.TracingConfig.Mode == lambdatypes.TracingModeActive {
		base.Status = fix.FixSkipped
		base.Message = "X-Ray active tracing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable X-Ray active tracing on function %s", resourceID)}
		return base
	}

	_, err = f.clients.Lambda.UpdateFunctionConfiguration(fctx.Ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(resourceID),
		TracingConfig: &lambdatypes.TracingConfig{
			Mode: lambdatypes.TracingModeActive,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update function configuration: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled X-Ray active tracing on function %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
