package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
)

func RegisterAppRunnerChecks(d *awsdata.Data) {
	// apprunner-service-in-vpc
	checker.Register(ConfigCheck(
		"apprunner-service-in-vpc",
		"Checks if AWS App Runner services route egress traffic through custom VPC. The rule is NON_COMPLIANT if configuration.NetworkConfiguration.EgressConfiguration.EgressType is equal to DEFAULT.",
		"apprunner",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			services, err := d.AppRunnerServiceDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, svc := range services {
				egressType := apprunnertypes.EgressTypeDefault
				if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.EgressConfiguration != nil {
					egressType = svc.NetworkConfiguration.EgressConfiguration.EgressType
				}
				ok := egressType == apprunnertypes.EgressTypeVpc
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("EgressType: %s", egressType)})
			}
			return res, nil
		},
	))

	// apprunner-service-ip-address-type-check
	checker.Register(ConfigCheck(
		"apprunner-service-ip-address-type-check",
		"Checks if an AWS App Runner service is configured with the specified IP address type for incoming public network configuration. The rule is NON_COMPLIANT if the service is not configured with the IP address type specified in the required rule parameter.",
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
		"Checks if an AWS App Runner service is configured to have an unhealthy threshold less than or equal to the specified value. The rule is NON_COMPLIANT if the unhealthy threshold is greater than the value specified in the required rule parameter.",
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
		"Checks if AWS AppRunner Services are not publicly accessible. The rule is NON_COMPLIANT if service.configuration.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible is False.",
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
		"Checks if AWS App Runner services have observability enabled. The rule is NON_COMPLIANT if configuration.ObservabilityConfiguration.ObservabilityEnabled is false'.",
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
		"Checks if AWS App Runner services have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS App Runner VPC connectors have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
