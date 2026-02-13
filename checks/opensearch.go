package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	opentypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

func RegisterOpenSearchChecks(d *awsdata.Data) {
	// opensearch-access-control-enabled
	checker.Register(ConfigCheck(
		"opensearch-access-control-enabled",
		"Checks if Amazon OpenSearch Service domains have fine-grained access control enabled. The rule is NON_COMPLIANT if AdvancedSecurityOptions is not enabled for the OpenSearch Service domain.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.AdvancedSecurityOptions != nil && dom.AdvancedSecurityOptions.Enabled != nil && *dom.AdvancedSecurityOptions.Enabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Advanced security enabled"})
			}
			return res, nil
		},
	))

	// opensearch-audit-logging-enabled + opensearch-logs-to-cloudwatch
	checker.Register(LoggingCheck(
		"opensearch-audit-logging-enabled",
		"Checks if Amazon OpenSearch Service domains have audit logging enabled. The rule is NON_COMPLIANT if an OpenSearch Service domain does not have audit logging enabled.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, dom := range domains {
				id := *dom.DomainName
				logging := false
				if dom.LogPublishingOptions != nil {
					if opt, ok := dom.LogPublishingOptions[string(opentypes.LogTypeAuditLogs)]; ok {
						logging = opt.Enabled != nil && *opt.Enabled
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(LoggingCheck(
		"opensearch-logs-to-cloudwatch",
		"Checks if Amazon OpenSearch Service domains are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if logging is not configured.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, dom := range domains {
				id := *dom.DomainName
				logging := false
				if dom.LogPublishingOptions != nil {
					for _, opt := range dom.LogPublishingOptions {
						if opt.Enabled != nil && *opt.Enabled {
							logging = true
							break
						}
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	// opensearch-encrypted-at-rest
	checker.Register(EncryptionCheck(
		"opensearch-encrypted-at-rest",
		"Checks if Amazon OpenSearch Service domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, dom := range domains {
				id := *dom.DomainName
				encrypted := dom.EncryptionAtRestOptions != nil && dom.EncryptionAtRestOptions.Enabled != nil && *dom.EncryptionAtRestOptions.Enabled
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// opensearch-node-to-node-encryption-check
	checker.Register(EncryptionCheck(
		"opensearch-node-to-node-encryption-check",
		"Check if Amazon OpenSearch Service nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is not enabled on the domain",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, dom := range domains {
				id := *dom.DomainName
				encrypted := dom.NodeToNodeEncryptionOptions != nil && dom.NodeToNodeEncryptionOptions.Enabled != nil && *dom.NodeToNodeEncryptionOptions.Enabled
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// opensearch-https-required
	checker.Register(ConfigCheck(
		"opensearch-https-required",
		"Checks whether connections to OpenSearch domains are using HTTPS. The rule is NON_COMPLIANT if the Amazon OpenSearch domain 'EnforceHTTPS' is not 'true' or is 'true' and 'TLSSecurityPolicy' is not in 'tlsPolicies'.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.DomainEndpointOptions != nil && dom.DomainEndpointOptions.EnforceHTTPS != nil && *dom.DomainEndpointOptions.EnforceHTTPS
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "EnforceHTTPS"})
			}
			return res, nil
		},
	))

	// opensearch-in-vpc-only
	checker.Register(ConfigCheck(
		"opensearch-in-vpc-only",
		"Checks if Amazon OpenSearch Service domains are in an Amazon Virtual Private Cloud (VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.VPCOptions != nil && len(dom.VPCOptions.SubnetIds) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "VPC configured"})
			}
			return res, nil
		},
	))

	// opensearch-data-node-fault-tolerance + opensearch-primary-node-fault-tolerance
	checker.Register(ConfigCheck(
		"opensearch-data-node-fault-tolerance",
		"Checks if Amazon OpenSearch Service domains are configured with at least three data nodes and zoneAwarenessEnabled is true. The rule is NON_COMPLIANT for an OpenSearch domain if 'instanceCount' is less than 3 or 'zoneAwarenessEnabled' is set to 'false'.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.ClusterConfig != nil &&
					dom.ClusterConfig.ZoneAwarenessEnabled != nil && *dom.ClusterConfig.ZoneAwarenessEnabled &&
					dom.ClusterConfig.InstanceCount != nil && *dom.ClusterConfig.InstanceCount >= 3
				count := int32(0)
				if dom.ClusterConfig != nil && dom.ClusterConfig.InstanceCount != nil {
					count = *dom.ClusterConfig.InstanceCount
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Zone awareness enabled with instance count: %d", count)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"opensearch-primary-node-fault-tolerance",
		"Checks if Amazon OpenSearch Service domains are configured with at least three dedicated primary nodes. The rule is NON_COMPLIANT for an OpenSearch Service domain if 'DedicatedMasterEnabled' is set to 'false', or 'DedicatedMasterCount' is less than 3.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.ClusterConfig != nil && dom.ClusterConfig.DedicatedMasterEnabled != nil && *dom.ClusterConfig.DedicatedMasterEnabled && dom.ClusterConfig.DedicatedMasterCount != nil && *dom.ClusterConfig.DedicatedMasterCount >= 3
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Dedicated masters: %v", dom.ClusterConfig.DedicatedMasterCount)})
			}
			return res, nil
		},
	))

	// opensearch-update-check
	checker.Register(ConfigCheck(
		"opensearch-update-check",
		"Checks if Amazon OpenSearch Service version updates are available but not installed. The rule is NON_COMPLIANT for an OpenSearch domain if the latest software updates are not installed.",
		"opensearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.OpenSearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := *dom.DomainName
				ok := dom.ServiceSoftwareOptions != nil && dom.ServiceSoftwareOptions.UpdateAvailable != nil && !*dom.ServiceSoftwareOptions.UpdateAvailable
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "UpdateAvailable false"})
			}
			return res, nil
		},
	))
}
