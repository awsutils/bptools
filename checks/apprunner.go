package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

func RegisterAppRunnerChecks(d *awsdata.Data) {
	// apprunner-service-in-vpc
	checker.Register(ConfigCheck(
		"apprunner-service-in-vpc",
		"This rule checks App Runner service is in VPC.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, svc := range services {
				ok := svc.NetworkConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration.VpcConnectorArn != nil
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "VpcConnectorArn set"})
			}
			return res, nil
		},
	))

	// apprunner-service-ip-address-type-check
	checker.Register(ConfigCheck(
		"apprunner-service-ip-address-type-check",
		"This rule checks App Runner service IP address type.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, svc := range services {
				val := ""
				if svc.NetworkConfiguration != nil {
					val = string(svc.NetworkConfiguration.IpAddressType)
				}
				ok := val != ""
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("IpAddressType: %s", val)})
			}
			return res, nil
		},
	))

	// apprunner-service-max-unhealthy-threshold
	checker.Register(ConfigCheck(
		"apprunner-service-max-unhealthy-threshold",
		"This rule checks App Runner service max unhealthy threshold.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, svc := range services {
				val := int32(0)
				if svc.HealthCheckConfiguration != nil && svc.HealthCheckConfiguration.UnhealthyThreshold != nil {
					val = *svc.HealthCheckConfiguration.UnhealthyThreshold
				}
				ok := val > 0 && val <= 5
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("UnhealthyThreshold: %d", val)})
			}
			return res, nil
		},
	))

	// apprunner-service-no-public-access
	checker.Register(ConfigCheck(
		"apprunner-service-no-public-access",
		"This rule checks App Runner service no public access.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, svc := range services {
				public := false
				if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.IngressConfiguration != nil {
					public = svc.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible
				}
				res = append(res, ConfigResource{ID: arn, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))

	// apprunner-service-observability-enabled
	checker.Register(EnabledCheck(
		"apprunner-service-observability-enabled",
		"This rule checks App Runner service observability enabled.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, svc := range services {
				enabled := svc.ObservabilityConfiguration != nil && svc.ObservabilityConfiguration.ObservabilityEnabled
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	// apprunner-service-tagged
	checker.Register(TaggedCheck(
		"apprunner-service-tagged",
		"This rule checks tagging for App Runner service exist.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppRunnerServiceTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range services {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))

	// apprunner-vpc-connector-tagged
	checker.Register(TaggedCheck(
		"apprunner-vpc-connector-tagged",
		"This rule checks tagging for App Runner VPC connector exist.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			vpcs, err := d.AppRunnerVPCConnectors.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppRunnerVPCConnectorTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, vc := range vpcs {
				if vc.VpcConnectorArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *vc.VpcConnectorArn, Tags: tags[*vc.VpcConnectorArn]})
			}
			return res, nil
		},
	))
}
