package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
)

// RegisterCodeDeployChecks registers CodeDeploy checks.
func RegisterCodeDeployChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"codedeploy-auto-rollback-monitor-enabled",
		"This rule checks enabled state for codedeploy auto rollback monitor.",
		"codedeploy",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			groups, err := d.CodeDeployDeploymentGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for key, g := range groups {
				enabled := false
				if g.DeploymentGroupInfo != nil && g.DeploymentGroupInfo.AutoRollbackConfiguration != nil {
					enabled = g.DeploymentGroupInfo.AutoRollbackConfiguration.Enabled
					if enabled && len(g.DeploymentGroupInfo.AutoRollbackConfiguration.Events) == 0 {
						enabled = false
					}
				}
				res = append(res, EnabledResource{ID: key, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"codedeploy-deployment-group-auto-rollback-enabled",
		"This rule checks enabled state for codedeploy deployment group auto rollback.",
		"codedeploy",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			groups, err := d.CodeDeployDeploymentGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for key, g := range groups {
				enabled := g.DeploymentGroupInfo != nil && g.DeploymentGroupInfo.AutoRollbackConfiguration != nil && g.DeploymentGroupInfo.AutoRollbackConfiguration.Enabled
				res = append(res, EnabledResource{ID: key, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codedeploy-deployment-group-outdated-instances-update",
		"This rule checks codedeploy deployment group outdated instances update.",
		"codedeploy",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.CodeDeployDeploymentGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, g := range groups {
				strategy := codedeploytypes.OutdatedInstancesStrategyIgnore
				if g.DeploymentGroupInfo != nil && g.DeploymentGroupInfo.OutdatedInstancesStrategy != "" {
					strategy = g.DeploymentGroupInfo.OutdatedInstancesStrategy
				}
				ok := strategy == codedeploytypes.OutdatedInstancesStrategyUpdate
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: fmt.Sprintf("OutdatedInstancesStrategy: %s", strategy)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codedeploy-ec2-minimum-healthy-hosts-configured",
		"This rule checks codedeploy EC2 minimum healthy hosts configured.",
		"codedeploy",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.CodeDeployDeploymentGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			configs, err := d.CodeDeployDeploymentConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, g := range groups {
				if g.DeploymentGroupInfo == nil || g.DeploymentGroupInfo.ComputePlatform != codedeploytypes.ComputePlatformServer {
					continue
				}
				cfgName := ""
				if g.DeploymentGroupInfo.DeploymentConfigName != nil {
					cfgName = *g.DeploymentGroupInfo.DeploymentConfigName
				}
				cfg := configs[cfgName]
				ok := cfg.DeploymentConfigInfo != nil &&
					cfg.DeploymentConfigInfo.MinimumHealthyHosts != nil &&
					cfg.DeploymentConfigInfo.MinimumHealthyHosts.Value > 0
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: fmt.Sprintf("DeploymentConfig: %s", cfgName)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codedeploy-lambda-allatonce-traffic-shift-disabled",
		"This rule checks disabled state for codedeploy LAMBDA allatonce traffic shift.",
		"codedeploy",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.CodeDeployDeploymentGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, g := range groups {
				if g.DeploymentGroupInfo == nil || g.DeploymentGroupInfo.ComputePlatform != codedeploytypes.ComputePlatformLambda {
					continue
				}
				cfg := ""
				if g.DeploymentGroupInfo.DeploymentConfigName != nil {
					cfg = *g.DeploymentGroupInfo.DeploymentConfigName
				}
				ok := cfg != "CodeDeployDefault.LambdaAllAtOnce"
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: fmt.Sprintf("DeploymentConfig: %s", cfg)})
			}
			return res, nil
		},
	))
}
