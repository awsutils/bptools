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
		"Checks if Capacity Rebalancing is enabled for Amazon EC2 Auto Scaling groups that use multiple instance types. The rule is NON_COMPLIANT if capacity Rebalancing is not enabled.",
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
		"Checks if your Amazon EC2 Auto Scaling groups that are associated with an Elastic Load Balancer use Elastic Load Balancing health checks. The rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling groups are not using Elastic Load Balancing health checks.",
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
		"Checks if an Amazon Elastic Compute Cloud (EC2) Auto Scaling group is created from an EC2 launch template. The rule is NON_COMPLIANT if the scaling group is not created from an EC2 launch template.",
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
		"Checks if the Auto Scaling group spans multiple Availability Zones. The rule is NON_COMPLIANT if the Auto Scaling group does not span multiple Availability Zones.",
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
		"Checks if an Amazon EC2 Auto Scaling group uses multiple instance types. The rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling group has only one instance type defined. This rule does not evaluate attribute-based instance types.",
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
		"Checks whether only IMDSv2 is enabled. This rule is NON_COMPLIANT if the Metadata version is not included in the launch configuration or if both Metadata V1 and V2 are enabled.",
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
		"Checks the number of network hops that the metadata token can travel. This rule is NON_COMPLIANT if the Metadata response hop limit is greater than 1.",
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
				ok := hop <= 1 // 0 means unset (AWS default = 1, compliant); >1 is NON_COMPLIANT
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("HopLimit: %d", hop)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"autoscaling-launch-config-public-ip-disabled",
		"Checks if Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations. The rule is NON_COMPLIANT if the Launch Configuration for an Amazon EC2 Auto Scaling group has AssociatePublicIpAddress set to 'true'.",
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
