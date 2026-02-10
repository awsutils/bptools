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
		"This rule checks elasticsearch encrypted at rest.",
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
		"This rule checks elasticsearch in VPC only.",
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
		"This rule checks elasticsearch logs to CloudWatch.",
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
		"This rule checks configuration for elasticsearch node to node encryption.",
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
