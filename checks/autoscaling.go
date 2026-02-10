package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	autotypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	ecztypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
				ok := strings.EqualFold(healthCheckType, "ELB") || len(g.TargetGroupARNs) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("HealthCheckType: %s", healthCheckType)})
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
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				azCount := len(g.AvailabilityZones)
				subnetCount := 0
				if g.VPCZoneIdentifier != nil && *g.VPCZoneIdentifier != "" {
					subnetCount = len(strings.Split(*g.VPCZoneIdentifier, ","))
				}
				ok := azCount > 1 || subnetCount > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AZs: %d, Subnets: %d", azCount, subnetCount)})
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
				count := 1
				if g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil {
					count = len(g.MixedInstancesPolicy.LaunchTemplate.Overrides)
				}
				ok := count > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Instance type overrides: %d", count)})
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
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			versions, err := d.EC2LaunchTemplateVersions.Get()
			if err != nil {
				return nil, err
			}
			lcMap := make(map[string]autotypes.LaunchConfiguration)
			lcs, err := d.AutoScalingLaunchConfigs.Get()
			if err == nil {
				for _, lc := range lcs {
					if lc.LaunchConfigurationName != nil {
						lcMap[*lc.LaunchConfigurationName] = lc
					}
				}
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				if g.LaunchTemplate != nil && g.LaunchTemplate.LaunchTemplateId != nil {
					lt := versions[*g.LaunchTemplate.LaunchTemplateId]
					tokens := lt.LaunchTemplateData.MetadataOptions.HttpTokens
					ok := tokens == ecztypes.LaunchTemplateHttpTokensStateRequired
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("IMDSv2 tokens: %s", tokens)})
					continue
				}
				if g.LaunchConfigurationName != nil {
					_ = lcMap[*g.LaunchConfigurationName]
				}
				res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Launch config used"})
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
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			versions, err := d.EC2LaunchTemplateVersions.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				if g.LaunchTemplate != nil && g.LaunchTemplate.LaunchTemplateId != nil {
					lt := versions[*g.LaunchTemplate.LaunchTemplateId]
					hop := int32(0)
					if lt.LaunchTemplateData.MetadataOptions != nil && lt.LaunchTemplateData.MetadataOptions.HttpPutResponseHopLimit != nil {
						hop = *lt.LaunchTemplateData.MetadataOptions.HttpPutResponseHopLimit
					}
					ok := hop > 0 && hop <= 1
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("HopLimit: %d", hop)})
					continue
				}
				res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Launch config used"})
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
			groups, err := d.AutoScalingGroups.Get()
			if err != nil {
				return nil, err
			}
			versions, err := d.EC2LaunchTemplateVersions.Get()
			if err != nil {
				return nil, err
			}
			lcs, _ := d.AutoScalingLaunchConfigs.Get()
			lcMap := make(map[string]autotypes.LaunchConfiguration)
			for _, lc := range lcs {
				if lc.LaunchConfigurationName != nil {
					lcMap[*lc.LaunchConfigurationName] = lc
				}
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.AutoScalingGroupName != nil {
					id = *g.AutoScalingGroupName
				}
				if g.LaunchTemplate != nil && g.LaunchTemplate.LaunchTemplateId != nil {
					lt := versions[*g.LaunchTemplate.LaunchTemplateId]
					ok := true
					if lt.LaunchTemplateData.NetworkInterfaces != nil && len(lt.LaunchTemplateData.NetworkInterfaces) > 0 {
						for _, ni := range lt.LaunchTemplateData.NetworkInterfaces {
							if ni.AssociatePublicIpAddress != nil && *ni.AssociatePublicIpAddress {
								ok = false
							}
						}
					}
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Launch template public IP"})
					continue
				}
				if g.LaunchConfigurationName != nil {
					lc := lcMap[*g.LaunchConfigurationName]
					ok := lc.AssociatePublicIpAddress != nil && !*lc.AssociatePublicIpAddress
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AssociatePublicIpAddress: %v", lc.AssociatePublicIpAddress)})
					continue
				}
				res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No launch config"})
			}
			return res, nil
		},
	))
}
