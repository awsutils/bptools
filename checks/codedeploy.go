package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
)

// RegisterCodeDeployChecks registers CodeDeploy checks.
func RegisterCodeDeployChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"codedeploy-auto-rollback-monitor-enabled",
		"Checks if the deployment group is configured with automatic deployment rollback and deployment monitoring with alarms attached. The rule is NON_COMPLIANT if AutoRollbackConfiguration or AlarmConfiguration has not been configured or is not enabled.",
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
				if g.DeploymentGroupInfo != nil {
					hasAutoRollback := false
					if g.DeploymentGroupInfo.AutoRollbackConfiguration != nil {
						hasAutoRollback = g.DeploymentGroupInfo.AutoRollbackConfiguration.Enabled &&
							len(g.DeploymentGroupInfo.AutoRollbackConfiguration.Events) > 0
					}
					hasAlarmMonitor := false
					if g.DeploymentGroupInfo.AlarmConfiguration != nil {
						hasAlarmMonitor = g.DeploymentGroupInfo.AlarmConfiguration.Enabled &&
							len(g.DeploymentGroupInfo.AlarmConfiguration.Alarms) > 0
					}
					enabled = hasAutoRollback && hasAlarmMonitor
				}
				res = append(res, EnabledResource{ID: key, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"codedeploy-deployment-group-auto-rollback-enabled",
		"Checks if AWS CodeDeploy deployment groups have auto rollback configuration enabled. The rule is NON_COMPLIANT if configuration.autoRollbackConfiguration.enabled is false or does not exist.",
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
		"Checks if AWS CodeDeploy deployment groups automatically update outdated instances. The rule is NON_COMPLIANT if configuration.outdatedInstancesStrategy is 'IGNORE'.",
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
		"Checks if the deployment group for EC2/On-Premises Compute Platform is configured with a minimum healthy hosts fleet percentage or host count greater than or equal to the input threshold. The rule is NON_COMPLIANT if either is below the threshold.",
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
			minHostCount := int32(1)
			if v := strings.TrimSpace(os.Getenv("BPTOOLS_CODEDEPLOY_MIN_HEALTHY_HOST_COUNT")); v != "" {
				if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
					minHostCount = int32(parsed)
				}
			}
			minFleetPercent := int32(66)
			if v := strings.TrimSpace(os.Getenv("BPTOOLS_CODEDEPLOY_MIN_HEALTHY_FLEET_PERCENT")); v != "" {
				if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
					minFleetPercent = int32(parsed)
				}
			}
			for key, g := range groups {
				if g.DeploymentGroupInfo == nil || g.DeploymentGroupInfo.ComputePlatform != codedeploytypes.ComputePlatformServer {
					continue
				}
				cfgName := ""
				if g.DeploymentGroupInfo.DeploymentConfigName != nil {
					cfgName = *g.DeploymentGroupInfo.DeploymentConfigName
				}
				cfg := configs[cfgName]
				ok := false
				detail := fmt.Sprintf("DeploymentConfig: %s", cfgName)
				if cfg.DeploymentConfigInfo == nil || cfg.DeploymentConfigInfo.MinimumHealthyHosts == nil {
					detail += " (MinimumHealthyHosts missing)"
					res = append(res, ConfigResource{ID: key, Passing: false, Detail: detail})
					continue
				}
				minHealthy := cfg.DeploymentConfigInfo.MinimumHealthyHosts
				switch minHealthy.Type {
				case codedeploytypes.MinimumHealthyHostsTypeHostCount:
					ok = minHealthy.Value >= minHostCount
					detail = fmt.Sprintf("DeploymentConfig: %s, MinimumHealthyHosts HOST_COUNT=%d (required >= %d)", cfgName, minHealthy.Value, minHostCount)
				case codedeploytypes.MinimumHealthyHostsTypeFleetPercent:
					ok = minHealthy.Value >= minFleetPercent
					detail = fmt.Sprintf("DeploymentConfig: %s, MinimumHealthyHosts FLEET_PERCENT=%d (required >= %d)", cfgName, minHealthy.Value, minFleetPercent)
				default:
					ok = minHealthy.Value > 0
					detail = fmt.Sprintf("DeploymentConfig: %s, MinimumHealthyHosts %s=%d", cfgName, minHealthy.Type, minHealthy.Value)
				}
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codedeploy-lambda-allatonce-traffic-shift-disabled",
		"Checks if the deployment group for Lambda Compute Platform is not using the default deployment configuration. The rule is NON_COMPLIANT if the deployment group is using the deployment configuration 'CodeDeployDefault.LambdaAllAtOnce'.",
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
