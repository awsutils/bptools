package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	appconfigtypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	appConfigDefaultDescription = "Managed by bptools auto-remediation"
)

var appConfigDefaultTags = map[string]string{
	"bptools:managed-by": "bptools",
}

func appConfigParseTwoPartID(resourceID string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func appConfigAccountID(ctx fix.FixContext, clients *awsdata.Clients) (string, error) {
	out, err := clients.STS.GetCallerIdentity(ctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	if out.Account == nil || strings.TrimSpace(*out.Account) == "" {
		return "", fmt.Errorf("missing account ID from STS")
	}
	return *out.Account, nil
}

func appConfigResourceARN(clients *awsdata.Clients, accountID string, resourcePath string) string {
	region := clients.AppConfig.Options().Region
	return fmt.Sprintf("arn:aws:appconfig:%s:%s:%s", region, accountID, resourcePath)
}

func appConfigIsManagedDeploymentStrategyID(id string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(id)), "appconfig.")
}

type appConfigApplicationDescriptionFix struct{ clients *awsdata.Clients }

func (f *appConfigApplicationDescriptionFix) CheckID() string {
	return "appconfig-application-description"
}
func (f *appConfigApplicationDescriptionFix) Description() string {
	return "Set AppConfig application description"
}
func (f *appConfigApplicationDescriptionFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigApplicationDescriptionFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appConfigApplicationDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	appID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: appID, Impact: f.Impact(), Severity: f.Severity()}
	if appID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing application ID"
		return base
	}

	appOut, err := f.clients.AppConfig.GetApplication(fctx.Ctx, &appconfig.GetApplicationInput{ApplicationId: aws.String(appID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get application: " + err.Error()
		return base
	}
	if appOut.Description != nil && strings.TrimSpace(*appOut.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "application description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set description for AppConfig application %s", appID)}
		return base
	}

	_, err = f.clients.AppConfig.UpdateApplication(fctx.Ctx, &appconfig.UpdateApplicationInput{
		ApplicationId: aws.String(appID),
		Description:   aws.String(appConfigDefaultDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update application: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set description for AppConfig application %s", appID)}
	return base
}

type appConfigEnvironmentDescriptionFix struct{ clients *awsdata.Clients }

func (f *appConfigEnvironmentDescriptionFix) CheckID() string {
	return "appconfig-environment-description"
}
func (f *appConfigEnvironmentDescriptionFix) Description() string {
	return "Set AppConfig environment description"
}
func (f *appConfigEnvironmentDescriptionFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigEnvironmentDescriptionFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appConfigEnvironmentDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	appID, envID, ok := appConfigParseTwoPartID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected applicationId:environmentId)"
		return base
	}

	envOut, err := f.clients.AppConfig.GetEnvironment(fctx.Ctx, &appconfig.GetEnvironmentInput{
		ApplicationId: aws.String(appID),
		EnvironmentId: aws.String(envID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get environment: " + err.Error()
		return base
	}
	if envOut.Description != nil && strings.TrimSpace(*envOut.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "environment description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set description for AppConfig environment %s", resourceID)}
		return base
	}

	_, err = f.clients.AppConfig.UpdateEnvironment(fctx.Ctx, &appconfig.UpdateEnvironmentInput{
		ApplicationId: aws.String(appID),
		EnvironmentId: aws.String(envID),
		Description:   aws.String(appConfigDefaultDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update environment: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set description for AppConfig environment %s", resourceID)}
	return base
}

type appConfigDeploymentStrategyDescriptionFix struct{ clients *awsdata.Clients }

func (f *appConfigDeploymentStrategyDescriptionFix) CheckID() string {
	return "appconfig-deployment-strategy-description"
}
func (f *appConfigDeploymentStrategyDescriptionFix) Description() string {
	return "Set AppConfig deployment strategy description"
}
func (f *appConfigDeploymentStrategyDescriptionFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigDeploymentStrategyDescriptionFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appConfigDeploymentStrategyDescriptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	strategyID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: strategyID, Impact: f.Impact(), Severity: f.Severity()}
	if strategyID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing deployment strategy ID"
		return base
	}
	if appConfigIsManagedDeploymentStrategyID(strategyID) {
		base.Status = fix.FixSkipped
		base.Message = "AWS-managed deployment strategy cannot be updated"
		return base
	}

	out, err := f.clients.AppConfig.GetDeploymentStrategy(fctx.Ctx, &appconfig.GetDeploymentStrategyInput{
		DeploymentStrategyId: aws.String(strategyID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get deployment strategy: " + err.Error()
		return base
	}
	if out.Description != nil && strings.TrimSpace(*out.Description) != "" {
		base.Status = fix.FixSkipped
		base.Message = "deployment strategy description already set"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set description for AppConfig deployment strategy %s", strategyID)}
		return base
	}

	_, err = f.clients.AppConfig.UpdateDeploymentStrategy(fctx.Ctx, &appconfig.UpdateDeploymentStrategyInput{
		DeploymentStrategyId: aws.String(strategyID),
		Description:          aws.String(appConfigDefaultDescription),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update deployment strategy: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set description for AppConfig deployment strategy %s", strategyID)}
	return base
}

type appConfigTagFix struct {
	checkID string
	kind    string
	clients *awsdata.Clients
}

func (f *appConfigTagFix) CheckID() string     { return f.checkID }
func (f *appConfigTagFix) Description() string { return "Tag AppConfig resource" }
func (f *appConfigTagFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigTagFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appConfigTagFix) resourceARN(fctx fix.FixContext, resourceID string) (string, error) {
	accountID, err := appConfigAccountID(fctx, f.clients)
	if err != nil {
		return "", err
	}

	switch f.kind {
	case "application":
		return appConfigResourceARN(f.clients, accountID, "application/"+strings.TrimSpace(resourceID)), nil
	case "environment":
		appID, envID, ok := appConfigParseTwoPartID(resourceID)
		if !ok {
			return "", fmt.Errorf("invalid environment resource ID (expected applicationId:environmentId)")
		}
		return appConfigResourceARN(f.clients, accountID, "application/"+appID+"/environment/"+envID), nil
	case "configurationprofile":
		appID, profileID, ok := appConfigParseTwoPartID(resourceID)
		if !ok {
			return "", fmt.Errorf("invalid profile resource ID (expected applicationId:configurationProfileId)")
		}
		return appConfigResourceARN(f.clients, accountID, "application/"+appID+"/configurationprofile/"+profileID), nil
	case "deploymentstrategy":
		id := strings.TrimSpace(resourceID)
		if appConfigIsManagedDeploymentStrategyID(id) {
			return "", fmt.Errorf("AWS-managed deployment strategy cannot be updated")
		}
		return appConfigResourceARN(f.clients, accountID, "deploymentstrategy/"+id), nil
	case "extensionassociation":
		return appConfigResourceARN(f.clients, accountID, "extensionassociation/"+strings.TrimSpace(resourceID)), nil
	default:
		return "", fmt.Errorf("unsupported resource kind: %s", f.kind)
	}
}

func (f *appConfigTagFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.checkID, ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	arn, err := f.resourceARN(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve resource ARN: " + err.Error()
		return base
	}

	tagOut, err := f.clients.AppConfig.ListTagsForResource(fctx.Ctx, &appconfig.ListTagsForResourceInput{
		ResourceArn: aws.String(arn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list tags: " + err.Error()
		return base
	}
	if len(tagOut.Tags) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "resource already tagged"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would tag AppConfig resource %s", resourceID)}
		return base
	}

	_, err = f.clients.AppConfig.TagResource(fctx.Ctx, &appconfig.TagResourceInput{
		ResourceArn: aws.String(arn),
		Tags:        appConfigDefaultTags,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "tag resource: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("tagged AppConfig resource %s", resourceID)}
	return base
}

type appConfigValidatorsFix struct{ clients *awsdata.Clients }

func (f *appConfigValidatorsFix) CheckID() string {
	return "appconfig-configuration-profile-validators-not-empty"
}
func (f *appConfigValidatorsFix) Description() string {
	return "Attach default JSON_SCHEMA validator to AppConfig configuration profile"
}
func (f *appConfigValidatorsFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigValidatorsFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *appConfigValidatorsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	appID, profileID, ok := appConfigParseTwoPartID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected applicationId:configurationProfileId)"
		return base
	}

	out, err := f.clients.AppConfig.GetConfigurationProfile(fctx.Ctx, &appconfig.GetConfigurationProfileInput{
		ApplicationId:          aws.String(appID),
		ConfigurationProfileId: aws.String(profileID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get configuration profile: " + err.Error()
		return base
	}
	if len(out.Validators) > 0 {
		base.Status = fix.FixSkipped
		base.Message = "configuration profile already has validators"
		return base
	}

	validator := appconfigtypes.Validator{
		Type:    appconfigtypes.ValidatorTypeJsonSchema,
		Content: aws.String("{}"),
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would add JSON_SCHEMA validator to AppConfig profile %s", resourceID)}
		return base
	}

	_, err = f.clients.AppConfig.UpdateConfigurationProfile(fctx.Ctx, &appconfig.UpdateConfigurationProfileInput{
		ApplicationId:          aws.String(appID),
		ConfigurationProfileId: aws.String(profileID),
		Validators:             []appconfigtypes.Validator{validator},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update configuration profile validators: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("added JSON_SCHEMA validator to AppConfig profile %s", resourceID)}
	return base
}

type appConfigMinimumFinalBakeTimeFix struct{ clients *awsdata.Clients }

func (f *appConfigMinimumFinalBakeTimeFix) CheckID() string {
	return "appconfig-deployment-strategy-minimum-final-bake-time"
}
func (f *appConfigMinimumFinalBakeTimeFix) Description() string {
	return "Set AppConfig deployment strategy final bake time to at least 30 minutes"
}
func (f *appConfigMinimumFinalBakeTimeFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *appConfigMinimumFinalBakeTimeFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appConfigMinimumFinalBakeTimeFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	strategyID := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: strategyID, Impact: f.Impact(), Severity: f.Severity()}
	if strategyID == "" {
		base.Status = fix.FixFailed
		base.Message = "missing deployment strategy ID"
		return base
	}
	if appConfigIsManagedDeploymentStrategyID(strategyID) {
		base.Status = fix.FixSkipped
		base.Message = "AWS-managed deployment strategy cannot be updated"
		return base
	}

	out, err := f.clients.AppConfig.GetDeploymentStrategy(fctx.Ctx, &appconfig.GetDeploymentStrategyInput{
		DeploymentStrategyId: aws.String(strategyID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get deployment strategy: " + err.Error()
		return base
	}
	if out.FinalBakeTimeInMinutes >= 30 {
		base.Status = fix.FixSkipped
		base.Message = "deployment strategy final bake time already >= 30 minutes"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set final bake time to 30 minutes for AppConfig deployment strategy %s", strategyID)}
		return base
	}

	_, err = f.clients.AppConfig.UpdateDeploymentStrategy(fctx.Ctx, &appconfig.UpdateDeploymentStrategyInput{
		DeploymentStrategyId:   aws.String(strategyID),
		FinalBakeTimeInMinutes: aws.Int32(30),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update deployment strategy final bake time: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set final bake time to 30 minutes for AppConfig deployment strategy %s", strategyID)}
	return base
}
