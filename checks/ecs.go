package checks

import (
	"fmt"
	"os"
	"strconv"
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
				if ecsCapacityProviderIsAWSManagedOrDeleted(cp) {
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
				if ecsCapacityProviderIsAWSManagedOrDeleted(cp) {
					continue
				}
				id := "unknown"
				if cp.CapacityProviderArn != nil {
					id = *cp.CapacityProviderArn
				}
				prot := ""
				if cp.AutoScalingGroupProvider != nil {
					prot = string(cp.AutoScalingGroupProvider.ManagedTerminationProtection)
				}
				ok := prot == string(ecstypes.ManagedTerminationProtectionEnabled)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("ManagedTerminationProtection: %s", prot)})
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
			secretNames := ecsParseCSV(os.Getenv("BPTOOLS_ECS_ENV_SECRET_NAMES"))
			if len(secretNames) == 0 {
				secretNames = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "access_key", "private_key"}
			}
			for arn, td := range tasks {
				ok := true
				for _, c := range td.ContainerDefinitions {
					for _, env := range c.Environment {
						if env.Name == nil {
							continue
						}
						name := strings.ToLower(strings.TrimSpace(*env.Name))
						if name == "" {
							continue
						}
						if ecsEnvNameLooksSecret(name, secretNames) {
							ok = false
							break
						}
					}
					if !ok {
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Environment variables do not contain secret-like names"})
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
						ok = v.EfsVolumeConfiguration.TransitEncryption == ecstypes.EFSTransitEncryptionEnabled
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
					if !ecsContainerUserIsNonRoot(c.User) {
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
					if !ecsContainerUserIsNonRoot(c.User) {
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
				isWindows := td.RuntimePlatform != nil && strings.HasPrefix(string(td.RuntimePlatform.OperatingSystemFamily), "WINDOWS_")
				if !isWindows {
					res = append(res, ConfigResource{ID: arn, Passing: true, Detail: "Not Windows"})
					continue
				}
				ok := true
				for _, c := range td.ContainerDefinitions {
					if c.User == nil || strings.TrimSpace(*c.User) == "" || ecsWindowsUserIsAdmin(*c.User) {
						ok = false
						break
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
					if c.Privileged != nil && *c.Privileged {
						continue
					}
					if !ecsContainerUserIsNonRoot(c.User) {
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
					ok, detail := ecsFargatePlatformVersionCompliant(s)
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
				}
			}
			return res, nil
		},
	))
}

func ecsContainerUserIsNonRoot(user *string) bool {
	if user == nil {
		return false
	}
	value := strings.TrimSpace(*user)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if lower == "root" || lower == "0" || strings.HasPrefix(lower, "0:") {
		return false
	}
	return true
}

func ecsWindowsUserIsAdmin(user string) bool {
	normalized := strings.ToLower(strings.TrimSpace(user))
	return normalized == "administrator" || strings.HasSuffix(normalized, "\\administrator")
}

func ecsParseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(strings.ToLower(part))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func ecsEnvNameLooksSecret(name string, markers []string) bool {
	for _, marker := range markers {
		if marker != "" && strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func ecsFargatePlatformVersionCompliant(service ecstypes.Service) (bool, string) {
	if service.PlatformVersion == nil || strings.TrimSpace(*service.PlatformVersion) == "" || strings.EqualFold(strings.TrimSpace(*service.PlatformVersion), "LATEST") {
		return true, fmt.Sprintf("PlatformVersion: %v", service.PlatformVersion)
	}
	isWindows := service.PlatformFamily != nil && strings.Contains(strings.ToUpper(strings.TrimSpace(*service.PlatformFamily)), "WINDOWS")
	targetEnv := "BPTOOLS_ECS_FARGATE_LATEST_LINUX_VERSION"
	if isWindows {
		targetEnv = "BPTOOLS_ECS_FARGATE_LATEST_WINDOWS_VERSION"
	}
	target := strings.TrimSpace(os.Getenv(targetEnv))
	if target == "" {
		return true, fmt.Sprintf("PlatformVersion: %s (no %s configured)", strings.TrimSpace(*service.PlatformVersion), targetEnv)
	}
	currentParts, okCurrent := ecsVersionTuple(*service.PlatformVersion)
	targetParts, okTarget := ecsVersionTuple(target)
	if !okCurrent || !okTarget {
		return false, fmt.Sprintf("Unable to compare platform versions current=%s target=%s", strings.TrimSpace(*service.PlatformVersion), target)
	}
	for i := 0; i < len(currentParts) || i < len(targetParts); i++ {
		current := 0
		targetV := 0
		if i < len(currentParts) {
			current = currentParts[i]
		}
		if i < len(targetParts) {
			targetV = targetParts[i]
		}
		if current > targetV {
			return true, fmt.Sprintf("PlatformVersion: %s (>= %s)", strings.TrimSpace(*service.PlatformVersion), target)
		}
		if current < targetV {
			return false, fmt.Sprintf("PlatformVersion: %s (< %s)", strings.TrimSpace(*service.PlatformVersion), target)
		}
	}
	return true, fmt.Sprintf("PlatformVersion: %s (== %s)", strings.TrimSpace(*service.PlatformVersion), target)
}

func ecsVersionTuple(version string) ([]int, bool) {
	v := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(version), "v"))
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			break
		}
		numeric := ""
		for _, ch := range part {
			if ch >= '0' && ch <= '9' {
				numeric += string(ch)
				continue
			}
			break
		}
		if numeric == "" {
			return nil, false
		}
		n, err := strconv.Atoi(numeric)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func ecsCapacityProviderIsAWSManagedOrDeleted(cp ecstypes.CapacityProvider) bool {
	name := ""
	if cp.Name != nil {
		name = strings.ToUpper(strings.TrimSpace(*cp.Name))
	}
	if name == "FARGATE" || name == "FARGATE_SPOT" {
		return true
	}
	status := strings.ToUpper(strings.TrimSpace(string(cp.Status)))
	if status == "INACTIVE" {
		return true
	}
	updateStatus := strings.ToUpper(strings.TrimSpace(string(cp.UpdateStatus)))
	return strings.Contains(updateStatus, "DELETE")
}
