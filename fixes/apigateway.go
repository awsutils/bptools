package fixes

import (
	"errors"
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
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
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

// ── api-gw-rest-api-tagged ───────────────────────────────────────────────────

type apigwV1RestAPITagFix struct{ clients *awsdata.Clients }

func (f *apigwV1RestAPITagFix) CheckID() string { return "api-gw-rest-api-tagged" }
func (f *apigwV1RestAPITagFix) Description() string {
	return "Tag API Gateway REST API"
}
func (f *apigwV1RestAPITagFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1RestAPITagFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV1RestAPITagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	apiID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if apiID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing API ID"
		return base
	}
	region := f.clients.APIGateway.Options().Region
	arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID)

	tagsOut, err := f.clients.APIGateway.GetTags(fctx.Ctx, &apigateway.GetTagsInput{ResourceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "REST API already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag API Gateway REST API " + apiID}
		return base
	}

	_, err = f.clients.APIGateway.TagResource(fctx.Ctx, &apigateway.TagResourceInput{
		ResourceArn: aws.String(arn),
		Tags:        map[string]string{"bptools:managed-by": "bptools"},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag REST API: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged API Gateway REST API " + apiID}
	return base
}

// ── api-gw-stage-tagged ──────────────────────────────────────────────────────

type apigwV1StageTagFix struct{ clients *awsdata.Clients }

func (f *apigwV1StageTagFix) CheckID() string { return "api-gw-stage-tagged" }
func (f *apigwV1StageTagFix) Description() string {
	return "Tag API Gateway stage"
}
func (f *apigwV1StageTagFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1StageTagFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV1StageTagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}
	region := f.clients.APIGateway.Options().Region
	arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", region, restAPIID, stageName)

	tagsOut, err := f.clients.APIGateway.GetTags(fctx.Ctx, &apigateway.GetTagsInput{ResourceArn: aws.String(arn)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get tags: " + err.Error()
		return base
	}
	if len(tagsOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "stage already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would tag API Gateway stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGateway.TagResource(fctx.Ctx, &apigateway.TagResourceInput{
		ResourceArn: aws.String(arn),
		Tags:        map[string]string{"bptools:managed-by": "bptools"},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag stage: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"tagged API Gateway stage " + resourceID}
	return base
}

// ── api-gw-associated-with-waf ───────────────────────────────────────────────

type apigwV1WAFAssociationFix struct{ clients *awsdata.Clients }

func (f *apigwV1WAFAssociationFix) CheckID() string { return "api-gw-associated-with-waf" }
func (f *apigwV1WAFAssociationFix) Description() string {
	return "Associate a REGIONAL WAFv2 Web ACL to API Gateway stage"
}
func (f *apigwV1WAFAssociationFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *apigwV1WAFAssociationFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *apigwV1WAFAssociationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	restAPIID, stageName, ok := apigwV1StageID(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected restApiID:stageName): " + resourceID
		return base
	}
	region := f.clients.APIGateway.Options().Region
	stageARN := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", region, restAPIID, stageName)

	_, err := f.clients.WAFv2.GetWebACLForResource(fctx.Ctx, &wafv2.GetWebACLForResourceInput{
		ResourceArn: aws.String(stageARN),
	})
	if err == nil {
		base.Status = fix.FixSkipped
		base.Message = "stage already associated with a Web ACL"
		return base
	}
	var notFound *wafv2types.WAFNonexistentItemException
	if !errors.As(err, &notFound) {
		base.Status = fix.FixFailed
		base.Message = "get web ACL for resource: " + err.Error()
		return base
	}

	var webACLARNs []string
	var marker *string
	for {
		out, err := f.clients.WAFv2.ListWebACLs(fctx.Ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeRegional,
			NextMarker: marker,
			Limit:      aws.Int32(100),
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "list regional web ACLs: " + err.Error()
			return base
		}
		for _, acl := range out.WebACLs {
			if acl.ARN != nil && strings.TrimSpace(*acl.ARN) != "" {
				webACLARNs = append(webACLARNs, *acl.ARN)
			}
		}
		if out.NextMarker == nil || strings.TrimSpace(*out.NextMarker) == "" {
			break
		}
		marker = out.NextMarker
	}

	if len(webACLARNs) == 0 {
		base.Status = fix.FixFailed
		base.Message = "no REGIONAL WAFv2 Web ACL found to associate"
		return base
	}
	if len(webACLARNs) > 1 {
		base.Status = fix.FixFailed
		base.Message = "multiple REGIONAL WAFv2 Web ACLs found; refusing to auto-select"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would associate Web ACL %s to API Gateway stage %s", webACLARNs[0], resourceID)}
		return base
	}

	_, err = f.clients.WAFv2.AssociateWebACL(fctx.Ctx, &wafv2.AssociateWebACLInput{
		ResourceArn: aws.String(stageARN),
		WebACLArn:   aws.String(webACLARNs[0]),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "associate web ACL: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("associated Web ACL %s to API Gateway stage %s", webACLARNs[0], resourceID)}
	return base
}

// ── api-gwv2-authorization-type-configured ───────────────────────────────────

type apigwV2AuthorizationTypeFix struct{ clients *awsdata.Clients }

func (f *apigwV2AuthorizationTypeFix) CheckID() string {
	return "api-gwv2-authorization-type-configured"
}
func (f *apigwV2AuthorizationTypeFix) Description() string {
	return "Set API Gateway V2 route authorization type to AWS_IAM"
}
func (f *apigwV2AuthorizationTypeFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *apigwV2AuthorizationTypeFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV2AuthorizationTypeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	idx := strings.Index(resourceID, ":")
	if idx < 0 {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected apiID:routeID): " + resourceID
		return base
	}
	apiID := resourceID[:idx]
	routeID := resourceID[idx+1:]

	out, err := f.clients.APIGatewayV2.GetRoute(fctx.Ctx, &apigatewayv2.GetRouteInput{
		ApiId:   aws.String(apiID),
		RouteId: aws.String(routeID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get route: " + err.Error()
		return base
	}
	if out.AuthorizationType != apigwv2types.AuthorizationTypeNone {
		base.Status = fix.FixSkipped
		base.Message = "route authorization type already configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set authorization type AWS_IAM on API Gateway V2 route %s", resourceID)}
		return base
	}

	_, err = f.clients.APIGatewayV2.UpdateRoute(fctx.Ctx, &apigatewayv2.UpdateRouteInput{
		ApiId:             aws.String(apiID),
		RouteId:           aws.String(routeID),
		AuthorizationType: apigwv2types.AuthorizationTypeAwsIam,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update route authorization type: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set authorization type AWS_IAM on API Gateway V2 route %s", resourceID)}
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

// ── api-gw-cache-enabled-and-encrypted ───────────────────────────────────────

type apigwV1CacheEncryptedFix struct{ clients *awsdata.Clients }

func (f *apigwV1CacheEncryptedFix) CheckID() string {
	return "api-gw-cache-enabled-and-encrypted"
}
func (f *apigwV1CacheEncryptedFix) Description() string {
	return "Enable API Gateway V1 stage caching and method cache encryption"
}
func (f *apigwV1CacheEncryptedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1CacheEncryptedFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV1CacheEncryptedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
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
	alreadyOK := out.CacheClusterEnabled && len(out.MethodSettings) > 0
	for _, ms := range out.MethodSettings {
		if !(ms.CachingEnabled && ms.CacheDataEncrypted) {
			alreadyOK = false
			break
		}
	}
	if alreadyOK {
		base.Status = fix.FixSkipped
		base.Message = "stage cache and method cache encryption already enabled"
		return base
	}

	ops := []apigwtypes.PatchOperation{
		{Op: apigwtypes.OpReplace, Path: aws.String("/cacheClusterEnabled"), Value: aws.String("true")},
		{Op: apigwtypes.OpReplace, Path: aws.String("/cacheClusterSize"), Value: aws.String("0.5")},
		{Op: apigwtypes.OpReplace, Path: aws.String("/*/*/caching/enabled"), Value: aws.String("true")},
		{Op: apigwtypes.OpReplace, Path: aws.String("/*/*/caching/dataEncrypted"), Value: aws.String("true")},
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would enable stage cache cluster for API Gateway stage %s", resourceID),
			fmt.Sprintf("would enable and encrypt method-level cache for API Gateway stage %s", resourceID),
		}
		return base
	}

	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId:       aws.String(restAPIID),
		StageName:       aws.String(stageName),
		PatchOperations: ops,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage cache settings: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{
		fmt.Sprintf("enabled stage cache cluster for API Gateway stage %s", resourceID),
		fmt.Sprintf("enabled and encrypted method-level cache for API Gateway stage %s", resourceID),
	}
	return base
}

// ── api-gw-endpoint-type-check ────────────────────────────────────────────────

type apigwV1EndpointTypeFix struct{ clients *awsdata.Clients }

func (f *apigwV1EndpointTypeFix) CheckID() string { return "api-gw-endpoint-type-check" }
func (f *apigwV1EndpointTypeFix) Description() string {
	return "Set API Gateway REST API endpoint type to REGIONAL"
}
func (f *apigwV1EndpointTypeFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *apigwV1EndpointTypeFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *apigwV1EndpointTypeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	apiID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: apiID, Impact: f.Impact(), Severity: f.Severity()}
	if apiID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing API ID"
		return base
	}

	out, err := f.clients.APIGateway.GetRestApi(fctx.Ctx, &apigateway.GetRestApiInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get REST API: " + err.Error()
		return base
	}
	for _, t := range out.EndpointConfiguration.Types {
		if t == apigwtypes.EndpointTypeRegional || t == apigwtypes.EndpointTypePrivate {
			base.Status = fix.FixSkipped
			base.Message = "endpoint type already compliant"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would change API Gateway endpoint type to REGIONAL for REST API %s", apiID)}
		return base
	}

	candidates := [][]apigwtypes.PatchOperation{
		{
			{Op: apigwtypes.OpReplace, Path: aws.String("/endpointConfiguration/types/EDGE"), Value: aws.String("REGIONAL")},
		},
		{
			{Op: apigwtypes.OpReplace, Path: aws.String("/endpointConfiguration/types"), Value: aws.String("REGIONAL")},
		},
	}
	var lastErr error
	for _, ops := range candidates {
		_, err = f.clients.APIGateway.UpdateRestApi(fctx.Ctx, &apigateway.UpdateRestApiInput{
			RestApiId:       aws.String(apiID),
			PatchOperations: ops,
		})
		if err == nil {
			base.Status = fix.FixApplied
			base.Steps = []string{fmt.Sprintf("changed API Gateway endpoint type to REGIONAL for REST API %s", apiID)}
			return base
		}
		lastErr = err
	}

	base.Status = fix.FixFailed
	if lastErr != nil {
		base.Message = "update REST API endpoint type: " + lastErr.Error()
	} else {
		base.Message = "update REST API endpoint type failed"
	}
	return base
}

// ── api-gw-ssl-enabled ────────────────────────────────────────────────────────

type apigwV1SSLFix struct{ clients *awsdata.Clients }

func (f *apigwV1SSLFix) CheckID() string { return "api-gw-ssl-enabled" }
func (f *apigwV1SSLFix) Description() string {
	return "Generate and attach client certificate to API Gateway V1 stage"
}
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

// ── apigateway-stage-description ─────────────────────────────────────────────

type apigwV1StageDescriptionFix struct{ clients *awsdata.Clients }

func (f *apigwV1StageDescriptionFix) CheckID() string { return "apigateway-stage-description" }
func (f *apigwV1StageDescriptionFix) Description() string {
	return "Set description on API Gateway V1 stage"
}
func (f *apigwV1StageDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV1StageDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV1StageDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
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
	if out.Description != nil && strings.TrimSpace(*out.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "stage description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on API Gateway stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGateway.UpdateStage(fctx.Ctx, &apigateway.UpdateStageInput{
		RestApiId: aws.String(restAPIID),
		StageName: aws.String(stageName),
		PatchOperations: []apigwtypes.PatchOperation{
			{Op: apigwtypes.OpReplace, Path: aws.String("/description"), Value: aws.String("Managed by bptools auto-remediation")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage description: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on API Gateway stage " + resourceID}
	return base
}

// ── apigatewayv2-stage-description ───────────────────────────────────────────

type apigwV2StageDescriptionFix struct{ clients *awsdata.Clients }

func (f *apigwV2StageDescriptionFix) CheckID() string { return "apigatewayv2-stage-description" }
func (f *apigwV2StageDescriptionFix) Description() string {
	return "Set description on API Gateway V2 stage"
}
func (f *apigwV2StageDescriptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *apigwV2StageDescriptionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *apigwV2StageDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

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
	if out.Description != nil && strings.TrimSpace(*out.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "stage description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set description on API Gateway V2 stage " + resourceID}
		return base
	}

	_, err = f.clients.APIGatewayV2.UpdateStage(fctx.Ctx, &apigatewayv2.UpdateStageInput{
		ApiId:       aws.String(apiID),
		StageName:   aws.String(stageName),
		Description: aws.String("Managed by bptools auto-remediation"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update stage description: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set description on API Gateway V2 stage " + resourceID}
	return base
}
