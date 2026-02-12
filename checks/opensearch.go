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
		"This rule checks OpenSearch access control enabled.",
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
		"This rule checks OpenSearch audit logging enabled.",
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
		"This rule checks OpenSearch logs to CloudWatch.",
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
		"This rule checks OpenSearch encrypted at rest.",
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
		"This rule checks OpenSearch node-to-node encryption.",
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
		"This rule checks OpenSearch HTTPS required.",
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
		"This rule checks OpenSearch in VPC only.",
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
		"This rule checks OpenSearch data node fault tolerance.",
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
		"This rule checks OpenSearch primary node fault tolerance.",
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
		"This rule checks OpenSearch update status.",
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
