package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
)

// splitCodeDeployKey splits "appName:groupName" into its two parts.
func splitCodeDeployKey(resourceID string) (app, group string, ok bool) {
	idx := strings.Index(resourceID, ":")
	if idx < 0 {
		return "", "", false
	}
	return resourceID[:idx], resourceID[idx+1:], true
}

// ── codedeploy-deployment-group-auto-rollback-enabled ────────────────────────

type codeDeployAutoRollbackFix struct{ clients *awsdata.Clients }

func (f *codeDeployAutoRollbackFix) CheckID() string {
	return "codedeploy-deployment-group-auto-rollback-enabled"
}
func (f *codeDeployAutoRollbackFix) Description() string {
	return "Enable auto rollback on CodeDeploy deployment group"
}
func (f *codeDeployAutoRollbackFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeDeployAutoRollbackFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *codeDeployAutoRollbackFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	app, group, ok := splitCodeDeployKey(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected appName:groupName): " + resourceID
		return base
	}

	out, err := f.clients.CodeDeploy.GetDeploymentGroup(fctx.Ctx, &codedeploy.GetDeploymentGroupInput{
		ApplicationName:     aws.String(app),
		DeploymentGroupName: aws.String(group),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get deployment group: " + err.Error()
		return base
	}
	if out.DeploymentGroupInfo != nil && out.DeploymentGroupInfo.AutoRollbackConfiguration != nil &&
		out.DeploymentGroupInfo.AutoRollbackConfiguration.Enabled {
		base.Status = fix.FixSkipped
		base.Message = "auto rollback already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable auto rollback (DEPLOYMENT_FAILURE) on CodeDeploy deployment group " + resourceID}
		return base
	}

	_, err = f.clients.CodeDeploy.UpdateDeploymentGroup(fctx.Ctx, &codedeploy.UpdateDeploymentGroupInput{
		ApplicationName:            aws.String(app),
		CurrentDeploymentGroupName: aws.String(group),
		AutoRollbackConfiguration: &codedeploytypes.AutoRollbackConfiguration{
			Enabled: true,
			Events:  []codedeploytypes.AutoRollbackEvent{codedeploytypes.AutoRollbackEventDeploymentFailure},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update deployment group: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled auto rollback (DEPLOYMENT_FAILURE) on CodeDeploy deployment group " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── codedeploy-deployment-group-outdated-instances-update ────────────────────

type codeDeployOutdatedInstancesFix struct{ clients *awsdata.Clients }

func (f *codeDeployOutdatedInstancesFix) CheckID() string {
	return "codedeploy-deployment-group-outdated-instances-update"
}
func (f *codeDeployOutdatedInstancesFix) Description() string {
	return "Set outdated instances strategy to UPDATE on CodeDeploy deployment group"
}
func (f *codeDeployOutdatedInstancesFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeDeployOutdatedInstancesFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *codeDeployOutdatedInstancesFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	app, group, ok := splitCodeDeployKey(resourceID)
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format (expected appName:groupName): " + resourceID
		return base
	}

	out, err := f.clients.CodeDeploy.GetDeploymentGroup(fctx.Ctx, &codedeploy.GetDeploymentGroupInput{
		ApplicationName:     aws.String(app),
		DeploymentGroupName: aws.String(group),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get deployment group: " + err.Error()
		return base
	}
	if out.DeploymentGroupInfo != nil && out.DeploymentGroupInfo.OutdatedInstancesStrategy == codedeploytypes.OutdatedInstancesStrategyUpdate {
		base.Status = fix.FixSkipped
		base.Message = "outdated instances strategy already set to UPDATE"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set OutdatedInstancesStrategy=UPDATE on CodeDeploy deployment group " + resourceID}
		return base
	}

	_, err = f.clients.CodeDeploy.UpdateDeploymentGroup(fctx.Ctx, &codedeploy.UpdateDeploymentGroupInput{
		ApplicationName:            aws.String(app),
		CurrentDeploymentGroupName: aws.String(group),
		OutdatedInstancesStrategy:  codedeploytypes.OutdatedInstancesStrategyUpdate,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update deployment group: " + err.Error()
		return base
	}
	base.Steps = []string{"set OutdatedInstancesStrategy=UPDATE on CodeDeploy deployment group " + resourceID}
	base.Status = fix.FixApplied
	return base
}
