package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ── api-gwv2-stage-default-route-detailed-metrics-enabled ────────────────────

type apigwV2MetricsFix struct{ clients *awsdata.Clients }

func (f *apigwV2MetricsFix) CheckID() string {
	return "api-gwv2-stage-default-route-detailed-metrics-enabled"
}
func (f *apigwV2MetricsFix) Description() string {
	return "Enable detailed metrics on API Gateway V2 stage default route"
}
func (f *apigwV2MetricsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV2MetricsFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV2MetricsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Resource ID format: "apiID:stageName"
	idx := strings.Index(resourceID, ":")
	if idx < 0 {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected apiID:stageName): " + resourceID
		return base
	}
	apiID := resourceID[:idx]
	stageName := resourceID[idx+1:]

	out, err := f.clients.APIGatewayV2.GetStage(fctx.Ctx, &apigatewayv2.GetStageInput{
		ApiId:     aws.String(apiID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get stage: " + err.Error()
		return base
	}
	if out.DefaultRouteSettings != nil && out.DefaultRouteSettings.DetailedMetricsEnabled != nil && *out.DefaultRouteSettings.DetailedMetricsEnabled {
		base.Status = fix.FixSkipped
		base.Message = "detailed metrics already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable detailed metrics on API Gateway V2 stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGatewayV2.UpdateStage(fctx.Ctx, &apigatewayv2.UpdateStageInput{
		ApiId:     aws.String(apiID),
		StageName: aws.String(stageName),
		DefaultRouteSettings: &apigwv2types.RouteSettings{
			DetailedMetricsEnabled: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled detailed metrics on API Gateway V2 stage " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// apigwV1StageID splits a "restApiID:stageName" resource ID.
func apigwV1StageID(resourceID string) (restAPIID, stageName string, ok bool) {
	idx := strings.Index(resourceID, ":")
	if idx < 0 {
		return "", "", false
	}
	return resourceID[:idx], resourceID[idx+1:], true
}

// ── api-gw-xray-enabled ───────────────────────────────────────────────────────

type apigwV1XRayFix struct{ clients *awsdata.Clients }

func (f *apigwV1XRayFix) CheckID() string {
	return "api-gw-xray-enabled"
}
func (f *apigwV1XRayFix) Description() string {
	return "Enable X-Ray tracing on API Gateway V1 stage"
}
func (f *apigwV1XRayFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1XRayFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV1XRayFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}

	out, err := f.clients.APIGateway.GetStage(fctx.Ctx, &apigateway.GetStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get stage: " + err.Error()
		return base
	}
	if out.TracingEnabled {
		base.Status = fix.FixSkipped
		base.Message = "X-Ray tracing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable X-Ray tracing on API Gateway stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
		PatchOperations: []apigwtypes.PatchOperation{
			{Op: apigwtypes.OpReplace, Path: aws.String("/tracingEnabled"), Value: aws.String("true")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled X-Ray tracing on API Gateway stage " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── api-gw-execution-logging-enabled ─────────────────────────────────────────

type apigwV1ExecutionLoggingFix struct{ clients *awsdata.Clients }

func (f *apigwV1ExecutionLoggingFix) CheckID() string {
	return "api-gw-execution-logging-enabled"
}
func (f *apigwV1ExecutionLoggingFix) Description() string {
	return "Enable execution logging (ERROR level) on API Gateway V1 stage"
}
func (f *apigwV1ExecutionLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1ExecutionLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV1ExecutionLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}

	out, err := f.clients.APIGateway.GetStage(fctx.Ctx, &apigateway.GetStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get stage: " + err.Error()
		return base
	}
	// Check all method settings for ERROR or INFO logging level
	alreadyOK := len(out.MethodSettings) > 0
	for _, ms := range out.MethodSettings {
		if ms.LoggingLevel == nil {
			alreadyOK = false
			break
		}
		level := strings.ToUpper(*ms.LoggingLevel)
		if level != "ERROR" && level != "INFO" {
			alreadyOK = false
			break
		}
	}
	if alreadyOK {
		base.Status = fix.FixSkipped
		base.Message = "execution logging already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set logging level to ERROR for all methods on API Gateway stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
		PatchOperations: []apigwtypes.PatchOperation{
			{Op: apigwtypes.OpReplace, Path: aws.String("/*/*/logging/loglevel"), Value: aws.String("ERROR")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage: " + err.Error()
		return base
	}
	base.Steps = []string{"set logging level to ERROR for all methods on API Gateway stage " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── api-gw-ssl-enabled ────────────────────────────────────────────────────────

type apigwV1SSLFix struct{ clients *awsdata.Clients }

func (f *apigwV1SSLFix) CheckID() string     { return "api-gw-ssl-enabled" }
func (f *apigwV1SSLFix) Description() string { return "Generate and attach client certificate to API Gateway V1 stage" }
func (f *apigwV1SSLFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1SSLFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV1SSLFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}

	stOut, err := f.clients.APIGateway.GetStage(fctx.Ctx, &apigateway.GetStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get API Gateway stage: " + err.Error()
		return base
	}
	if stOut.ClientCertificateId != nil && *stOut.ClientCertificateId != "" {
		base.Status = fix.FixSkipped
		base.Message = "client certificate already configured: " + *stOut.ClientCertificateId
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would generate and attach client certificate to API Gateway stage %s", resourceID)}
		return base
	}

	// Generate a new client certificate
	certOut, err := f.clients.APIGateway.GenerateClientCertificate(fctx.Ctx, &apigateway.GenerateClientCertificateInput{
		Description: aws.String("bptools-managed client certificate for stage " + resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "generate client certificate: " + err.Error()
		return base
	}

	// Attach it to the stage
	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
		PatchOperations: []apigwtypes.PatchOperation{
			{Op: apigwtypes.OpReplace, Path: aws.String("/clientCertificateId"), Value: certOut.ClientCertificateId},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "attach client certificate to stage: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("generated and attached client certificate %s to API Gateway stage %s", aws.ToString(certOut.ClientCertificateId), resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── apigateway-stage-access-logs-enabled ──────────────────────────────────────

type apigwV1AccessLogsFix struct{ clients *awsdata.Clients }

func (f *apigwV1AccessLogsFix) CheckID() string { return "apigateway-stage-access-logs-enabled" }
func (f *apigwV1AccessLogsFix) Description() string {
	return "Enable access logging on API Gateway V1 stage"
}
func (f *apigwV1AccessLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1AccessLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV1AccessLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}

	stOut, err := f.clients.APIGateway.GetStage(fctx.Ctx, &apigateway.GetStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get stage: " + err.Error()
		return base
	}
	if stOut.AccessLogSettings != nil && stOut.AccessLogSettings.DestinationArn != nil &&
		*stOut.AccessLogSettings.DestinationArn != "" {
		base.Status = fix.FixSkipped
		base.Message = "access logging already enabled"
		return base
	}

	region := f.clients.CloudWatchLogs.Options().Region
	callerOut, err := f.clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get caller identity: " + err.Error()
		return base
	}
	account := aws.ToString(callerOut.Account)

	logGroupName := "/aws/apigateway/" + restAPIID + "/" + stageName
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable access logging on API Gateway stage %s", resourceID),
		}
		return base
	}

	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
		PatchOperations: []apigwtypes.PatchOperation{
			{Op: apigwtypes.OpReplace, Path: aws.String("/accessLogSettings/destinationArn"), Value: aws.String(logGroupArn)},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("ensured log group %s exists", logGroupName),
		fmt.Sprintf("enabled access logging on API Gateway stage %s", resourceID),
	}
	base.Status = fix.FixApplied
	return base
}

// ── api-gwv2-access-logs-enabled ─────────────────────────────────────────────

type apigwV2AccessLogsFix struct{ clients *awsdata.Clients }

func (f *apigwV2AccessLogsFix) CheckID() string { return "api-gwv2-access-logs-enabled" }
func (f *apigwV2AccessLogsFix) Description() string {
	return "Enable access logging on API Gateway V2 stage"
}
func (f *apigwV2AccessLogsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV2AccessLogsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV2AccessLogsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	idx := strings.Index(resourceID, ":")
	if idx < 0 {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected apiID:stageName): " + resourceID
		return base
	}
	apiID := resourceID[:idx]
	stageName := resourceID[idx+1:]

	stOut, err := f.clients.APIGatewayV2.GetStage(fctx.Ctx, &apigatewayv2.GetStageInput{
		ApiId:     aws.String(apiID),
		StageName: aws.String(stageName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get stage: " + err.Error()
		return base
	}
	if stOut.AccessLogSettings != nil && stOut.AccessLogSettings.DestinationArn != nil &&
		*stOut.AccessLogSettings.DestinationArn != "" {
		base.Status = fix.FixSkipped
		base.Message = "access logging already enabled"
		return base
	}

	region := f.clients.CloudWatchLogs.Options().Region
	callerOut, err := f.clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get caller identity: " + err.Error()
		return base
	}
	account := aws.ToString(callerOut.Account)

	logGroupName := "/aws/apigateway/v2/" + apiID + "/" + stageName
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable access logging on API Gateway V2 stage %s", resourceID),
		}
		return base
	}

	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.APIGatewayV2.UpdateStage(fctx.Ctx, &apigatewayv2.UpdateStageInput{
		ApiId:     aws.String(apiID),
		StageName: aws.String(stageName),
		AccessLogSettings: &apigwv2types.AccessLogSettings{
			DestinationArn: aws.String(logGroupArn),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("ensured log group %s exists", logGroupName),
		fmt.Sprintf("enabled access logging on API Gateway V2 stage %s", resourceID),
	}
	base.Status = fix.FixApplied
	return base
}
