package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	estypes "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
)

// RegisterElasticsearchChecks registers Elasticsearch checks.
func RegisterElasticsearchChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"elasticsearch-encrypted-at-rest",
		"Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled.",
		"elasticsearch",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			domains, err := d.ElasticsearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, dom := range domains {
				id := esID(dom)
				encrypted := dom.EncryptionAtRestOptions != nil && dom.EncryptionAtRestOptions.Enabled != nil && *dom.EncryptionAtRestOptions.Enabled
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"elasticsearch-in-vpc-only",
		"Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains are in Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public.",
		"elasticsearch",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.ElasticsearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := esID(dom)
				ok := dom.VPCOptions != nil && dom.VPCOptions.VPCId != nil && *dom.VPCOptions.VPCId != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "VPC configured"})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"elasticsearch-logs-to-cloudwatch",
		"Checks if OpenSearch Service (previously called Elasticsearch) domains are configured to send logs to CloudWatch Logs. The rule is COMPLIANT if a log is enabled for an OpenSearch Service domain. The rule is NON_COMPLIANT if logging is not configured.",
		"elasticsearch",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			domains, err := d.ElasticsearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, dom := range domains {
				id := esID(dom)
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

	checker.Register(EncryptionCheck(
		"elasticsearch-node-to-node-encryption-check",
		"Check that Amazon OpenSearch Service nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is disabled on the domain.",
		"elasticsearch",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			domains, err := d.ElasticsearchDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, dom := range domains {
				id := esID(dom)
				encrypted := dom.NodeToNodeEncryptionOptions != nil && dom.NodeToNodeEncryptionOptions.Enabled != nil && *dom.NodeToNodeEncryptionOptions.Enabled
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))
}

func esID(dom estypes.ElasticsearchDomainStatus) string {
	if dom.DomainName != nil {
		return *dom.DomainName
	}
	if dom.DomainId != nil {
		return *dom.DomainId
	}
	return fmt.Sprintf("%v", dom.DomainId)
}
