package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	autotypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
)

func RegisterAutoScalingChecks(d *awsdata.Data) {
	// autoscaling-capacity-rebalancing
	checker.Register(EnabledCheck(
		"autoscaling-capacity-rebalancing",
		"This rule checks Auto Scaling capacity rebalancing.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				enabled := g.CapacityRebalance != nil && *g.CapacityRebalance
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// autoscaling-group-elb-healthcheck-required
	checker.Register(ConfigCheck(
		"autoscaling-group-elb-healthcheck-required",
		"This rule checks Auto Scaling group ELB healthcheck required.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				healthCheckType := ""
				if g.HealthCheckType != nil {
					healthCheckType = *g.HealthCheckType
				}
				attachedToLB := len(g.LoadBalancerNames) > 0 || len(g.TargetGroupARNs) > 0
				ok := !attachedToLB || strings.EqualFold(healthCheckType, "ELB")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("HealthCheckType: %s, attachedToLB: %v", healthCheckType, attachedToLB)})
			}
			return res, nil
		},
	))

	// autoscaling-launch-template
	checker.Register(ConfigCheck(
		"autoscaling-launch-template",
		"This rule checks Auto Scaling launch template.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				ok := g.LaunchTemplate != nil || g.MixedInstancesPolicy != nil
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Launch template configured"})
			}
			return res, nil
		},
	))

	// autoscaling-multiple-az
	checker.Register(ConfigCheck(
		"autoscaling-multiple-az",
		"This rule checks Auto Scaling group multiple AZ.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			subnets, err := d.EC2Subnets.Get()
			if err != nil {
				return nil, err
			}
			subnetAZ := make(map[string]string)
			for _, subnet := range subnets {
				if subnet.SubnetId == nil || subnet.AvailabilityZone == nil {
					continue
				}
				subnetAZ[strings.TrimSpace(*subnet.SubnetId)] = strings.TrimSpace(*subnet.AvailabilityZone)
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				azSet := make(map[string]bool)
				for _, az := range g.AvailabilityZones {
					value := strings.TrimSpace(az)
					if value != "" {
						azSet[value] = true
					}
				}
				if g.VPCZoneIdentifier != nil && *g.VPCZoneIdentifier != "" {
					for _, subnetID := range strings.Split(*g.VPCZoneIdentifier, ",") {
						key := strings.TrimSpace(subnetID)
						if key == "" {
							continue
						}
						if az := subnetAZ[key]; az != "" {
							azSet[az] = true
						}
					}
				}
				ok := len(azSet) > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Distinct AZ count: %d", len(azSet))})
			}
			return res, nil
		},
	))

	// autoscaling-multiple-instance-types
	checker.Register(ConfigCheck(
		"autoscaling-multiple-instance-types",
		"This rule checks Auto Scaling group multiple instance types.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				overrides := 0
				if g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil {
					overrides = len(g.MixedInstancesPolicy.LaunchTemplate.Overrides)
				}
				ok := overrides >= 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Instance type overrides: %d", overrides)})
			}
			return res, nil
		},
	))

	// autoscaling-launchconfig-requires-imdsv2 + autoscaling-launch-config-hop-limit + autoscaling-launch-config-public-ip-disabled
	checker.Register(ConfigCheck(
		"autoscaling-launchconfig-requires-imdsv2",
		"This rule checks Auto Scaling launch config requires IMDSv2.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lcs, err := d.AutoScalingLaunchConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lc := range lcs {
				id := "unknown"
				if lc.LaunchConfigurationName != nil {
					id = *lc.LaunchConfigurationName
				}
				tokens := autotypes.InstanceMetadataHttpTokensStateOptional
				if lc.MetadataOptions != nil {
					tokens = lc.MetadataOptions.HttpTokens
				}
				ok := lc.MetadataOptions != nil && tokens == autotypes.InstanceMetadataHttpTokensStateRequired
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("IMDSv2 tokens: %s", tokens)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"autoscaling-launch-config-hop-limit",
		"This rule checks Auto Scaling launch config hop limit.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lcs, err := d.AutoScalingLaunchConfigs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, lc := range lcs {
				id := "unknown"
				if lc.LaunchConfigurationName != nil {
					id = *lc.LaunchConfigurationName
				}
				hop := int32(0)
				if lc.MetadataOptions != nil && lc.MetadataOptions.HttpPutResponseHopLimit != nil {
					hop = *lc.MetadataOptions.HttpPutResponseHopLimit
				}
				ok := hop > 0 && hop <= 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("HopLimit: %d", hop)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"autoscaling-launch-config-public-ip-disabled",
		"This rule checks Auto Scaling launch config public IP disabled.",
		"autoscaling",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			lcs, _ := d.AutoScalingLaunchConfigs.Get()
			var res []ConfigResource
			for _, lc := range lcs {
				id := "unknown"
				if lc.LaunchConfigurationName != nil {
					id = *lc.LaunchConfigurationName
				}
				ok := lc.AssociatePublicIpAddress == nil || !*lc.AssociatePublicIpAddress
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AssociatePublicIpAddress: %v", lc.AssociatePublicIpAddress)})
			}
			return res, nil
		},
	))
}
