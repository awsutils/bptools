package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
)

// ── appsync-graphql-api-xray-enabled ─────────────────────────────────────────

type appsyncXRayFix struct{ clients *awsdata.Clients }

func (f *appsyncXRayFix) CheckID() string { return "appsync-graphql-api-xray-enabled" }
func (f *appsyncXRayFix) Description() string {
	return "Enable X-Ray tracing on AppSync GraphQL API"
}
func (f *appsyncXRayFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appsyncXRayFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *appsyncXRayFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Resource ID is the ARN: arn:aws:appsync:{region}:{account}:apis/{api-id}
	apiID := resourceID
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.Split(resourceID, "/")
		if len(parts) >= 2 {
			apiID = parts[len(parts)-1]
		}
	}

	out, err := f.clients.AppSync.GetGraphqlApi(fctx.Ctx, &appsync.GetGraphqlApiInput{
		ApiId: aws.String(apiID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get GraphQL API: " + err.Error()
		return base
	}
	api := out.GraphqlApi
	if api == nil {
		base.Status = fix.FixFailed
		base.Message = "GraphQL API not found"
		return base
	}
	if api.XrayEnabled {
		base.Status = fix.FixSkipped
		base.Message = "X-Ray tracing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable X-Ray tracing on AppSync API " + resourceID}
		return base
	}

	_, err = f.clients.AppSync.UpdateGraphqlApi(fctx.Ctx, &appsync.UpdateGraphqlApiInput{
		ApiId:              aws.String(apiID),
		Name:               api.Name,
		AuthenticationType: api.AuthenticationType,
		XrayEnabled:        true,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update GraphQL API: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled X-Ray tracing on AppSync GraphQL API " + resourceID}
	base.Status = fix.FixApplied
	return base
}
