package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
)

// ── apprunner-service-observability-enabled ───────────────────────────────────

const appRunnerObservConfigName = "bptools-xray-tracing"

type appRunnerObservabilityFix struct{ clients *awsdata.Clients }

func (f *appRunnerObservabilityFix) CheckID() string {
	return "apprunner-service-observability-enabled"
}
func (f *appRunnerObservabilityFix) Description() string {
	return "Enable X-Ray tracing observability on App Runner service"
}
func (f *appRunnerObservabilityFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appRunnerObservabilityFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *appRunnerObservabilityFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	svc, err := f.clients.AppRunner.DescribeService(fctx.Ctx, &apprunner.DescribeServiceInput{
		ServiceArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe service: " + err.Error()
		return base
	}
	if svc.Service != nil &&
		svc.Service.ObservabilityConfiguration != nil &&
		svc.Service.ObservabilityConfiguration.ObservabilityEnabled {
		base.Status = fix.FixSkipped
		base.Message = "observability already enabled"
		return base
	}

	// Find or create an observability configuration with X-Ray tracing.
	listOut, err := f.clients.AppRunner.ListObservabilityConfigurations(fctx.Ctx,
		&apprunner.ListObservabilityConfigurationsInput{
			ObservabilityConfigurationName: aws.String(appRunnerObservConfigName),
			LatestOnly:                     true,
		})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list observability configs: " + err.Error()
		return base
	}

	if fctx.DryRun {
		action := fmt.Sprintf("would create observability config %s", appRunnerObservConfigName)
		if len(listOut.ObservabilityConfigurationSummaryList) > 0 {
			action = fmt.Sprintf("would reuse observability config %s", appRunnerObservConfigName)
		}
		base.Status = fix.FixDryRun
		base.Steps = []string{
			action,
			fmt.Sprintf("would enable X-Ray tracing observability on App Runner service %s", resourceID),
		}
		return base
	}

	var configArn string
	var steps []string

	if len(listOut.ObservabilityConfigurationSummaryList) > 0 {
		configArn = aws.ToString(listOut.ObservabilityConfigurationSummaryList[0].ObservabilityConfigurationArn)
		steps = append(steps, fmt.Sprintf("reused observability config %s", appRunnerObservConfigName))
	} else {
		createOut, cerr := f.clients.AppRunner.CreateObservabilityConfiguration(fctx.Ctx,
			&apprunner.CreateObservabilityConfigurationInput{
				ObservabilityConfigurationName: aws.String(appRunnerObservConfigName),
				TraceConfiguration: &apprunnertypes.TraceConfiguration{
					Vendor: apprunnertypes.TracingVendorAwsxray,
				},
			})
		if cerr != nil {
			base.Status = fix.FixFailed
			base.Message = "create observability config: " + cerr.Error()
			return base
		}
		configArn = aws.ToString(createOut.ObservabilityConfiguration.ObservabilityConfigurationArn)
		steps = append(steps, fmt.Sprintf("created observability config %s with X-Ray tracing", appRunnerObservConfigName))
	}

	_, err = f.clients.AppRunner.UpdateService(fctx.Ctx, &apprunner.UpdateServiceInput{
		ServiceArn: aws.String(resourceID),
		ObservabilityConfiguration: &apprunnertypes.ServiceObservabilityConfiguration{
			ObservabilityEnabled:          true,
			ObservabilityConfigurationArn: aws.String(configArn),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}
	steps = append(steps, fmt.Sprintf("enabled X-Ray tracing observability on App Runner service %s", resourceID))
	base.Steps = steps
	base.Status = fix.FixApplied
	return base
}
