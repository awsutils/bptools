package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func RegisterECSChecks(d *awsdata.Data) {
	// ecs-container-insights-enabled
	checker.Register(EnabledCheck(
		"ecs-container-insights-enabled",
		"This rule checks ECS container insights enabled.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.ECSClusterDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, c := range clusters {
				enabled := false
				for _, s := range c.Settings {
					if s.Name == "containerInsights" && s.Value != nil && strings.ToLower(*s.Value) == "enabled" {
						enabled = true
						break
					}
				}
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	// ecs-capacity-provider-tagged + ecs-capacity-provider-termination-check
	checker.Register(TaggedCheck(
		"ecs-capacity-provider-tagged",
		"This rule checks ECS capacity provider tagged.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			cps, err := d.ECSCapacityProviders.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.ECSCapacityProviderTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, cp := range cps {
				if cp.CapacityProviderArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *cp.CapacityProviderArn, Tags: tags[*cp.CapacityProviderArn]})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"ecs-capacity-provider-termination-check",
		"This rule checks ECS capacity provider termination protection.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			cps, err := d.ECSCapacityProviders.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, cp := range cps {
				id := "unknown"
				if cp.CapacityProviderArn != nil {
					id = *cp.CapacityProviderArn
				}
				ok := cp.ManagedTerminationProtection == ecstypes.ManagedTerminationProtectionEnabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("ManagedTerminationProtection: %s", cp.ManagedTerminationProtection)})
			}
			return res, nil
		},
	))

	// Task definition checks
	taskDefs, _ := d.ECSTaskDefDetails.Get()
	_ = taskDefs

	checker.Register(ConfigCheck(
		"ecs-awsvpc-networking-enabled",
		"This rule checks ECS awsvpc networking enabled.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := td.NetworkMode == ecstypes.NetworkModeAwsvpc
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("NetworkMode: %s", td.NetworkMode)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-network-mode-not-host",
		"This rule checks ECS task definition network mode not host.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := td.NetworkMode != ecstypes.NetworkModeHost
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("NetworkMode: %s", td.NetworkMode)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-pid-mode-check",
		"This rule checks ECS task definition PID mode.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := td.PidMode == "" || td.PidMode != ecstypes.PidModeHost
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("PidMode: %s", td.PidMode)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-containers-nonprivileged",
		"This rule checks ECS containers non-privileged.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.Privileged != nil && *c.Privileged {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Privileged=false"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-containers-readonly-access",
		"This rule checks ECS containers readonly root filesystem.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.ReadonlyRootFilesystem == nil || !*c.ReadonlyRootFilesystem {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "ReadonlyRootFilesystem"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-no-environment-secrets",
		"This rule checks ECS no environment secrets.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if len(c.Secrets) > 0 {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Secrets empty"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-efs-encryption-enabled",
		"This rule checks ECS task definition EFS encryption enabled.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, v := range td.Volumes {
					if v.EfsVolumeConfiguration != nil {
						ok = v.EfsVolumeConfiguration.TransitEncryption == ecstypes.TransitEncryptionEnabled
						if !ok {
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "EFS transit encryption"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-log-configuration",
		"This rule checks ECS task definition log configuration.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.LogConfiguration == nil {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "LogConfiguration present"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-memory-hard-limit",
		"This rule checks ECS task definition memory hard limit.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.Memory == nil {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Memory hard limit"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-linux-user-non-root",
		"This rule checks ECS task definition linux user non-root.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.User == nil || *c.User == "0" {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "User non-root"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-nonroot-user",
		"This rule checks ECS task definition nonroot user.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.User == nil || *c.User == "0" {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "User non-root"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-windows-user-non-admin",
		"This rule checks ECS task definition windows user non-admin.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.OperatingSystemFamily == ecstypes.OSFamilyWindowsServer2019Full || c.OperatingSystemFamily == ecstypes.OSFamilyWindowsServer2022Full {
						if c.User == nil || strings.EqualFold(*c.User, "Administrator") {
							ok = false
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Windows user non-admin"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ecs-task-definition-user-for-host-mode-check",
		"This rule checks ECS task definition user for host mode.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.ECSTaskDefDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, td := range tasks {
				if td.NetworkMode != ecstypes.NetworkModeHost {
					res = append(res, ConfigResource{ID: arn, Passing: true, Detail: "Not host mode"})
					continue
				}
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.User == nil || *c.User == "0" {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "User set for host mode"})
			}
			return res, nil
		},
	))

	// ecs-fargate-latest-platform-version
	checker.Register(ConfigCheck(
		"ecs-fargate-latest-platform-version",
		"This rule checks ECS Fargate latest platform version.",
		"ecs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			servicesByCluster, err := d.ECSServicesByCluster.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, svcs := range servicesByCluster {
				for _, s := range svcs {
					if s.LaunchType != ecstypes.LaunchTypeFargate {
						continue
					}
					id := "unknown"
					if s.ServiceArn != nil {
						id = *s.ServiceArn
					}
					ok := s.PlatformVersion == nil || *s.PlatformVersion == "" || *s.PlatformVersion == "LATEST"
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PlatformVersion: %v", s.PlatformVersion)})
				}
			}
			return res, nil
		},
	))
}
