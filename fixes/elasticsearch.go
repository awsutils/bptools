package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	estypes "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
)

// elasticsearchFix applies a single UpdateElasticsearchDomainConfig change.
// Mirrors opensearchFix but targets the legacy Elasticsearch API.
type elasticsearchFix struct {
	checkID     string
	description string
	severity    fix.SeverityLevel
	alreadyOK   func(dom estypes.ElasticsearchDomainStatus) bool
	buildInput  func(domainName string) *elasticsearchservice.UpdateElasticsearchDomainConfigInput
	clients     *awsdata.Clients
}

func (f *elasticsearchFix) CheckID() string          { return f.checkID }
func (f *elasticsearchFix) Description() string      { return f.description }
func (f *elasticsearchFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *elasticsearchFix) Severity() fix.SeverityLevel { return f.severity }

func (f *elasticsearchFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Elasticsearch.DescribeElasticsearchDomain(fctx.Ctx, &elasticsearchservice.DescribeElasticsearchDomainInput{
		DomainName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Elasticsearch domain: " + err.Error()
		return base
	}
	if out.DomainStatus != nil && f.alreadyOK(*out.DomainStatus) {
		base.Status = fix.FixSkipped
		base.Message = f.checkID + " already satisfied"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would apply %s fix on Elasticsearch domain %s", f.checkID, resourceID)}
		return base
	}

	input := f.buildInput(resourceID)
	_, err = f.clients.Elasticsearch.UpdateElasticsearchDomainConfig(fctx.Ctx, input)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update Elasticsearch domain config: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("applied %s fix on Elasticsearch domain %s", f.checkID, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// newElasticsearchEncryptionAtRestFix fixes elasticsearch-encrypted-at-rest.
func newElasticsearchEncryptionAtRestFix(clients *awsdata.Clients) *elasticsearchFix {
	return &elasticsearchFix{
		checkID:     "elasticsearch-encrypted-at-rest",
		description: "Enable encryption at rest for Elasticsearch domain",
		severity:    fix.SeverityHigh,
		alreadyOK: func(d estypes.ElasticsearchDomainStatus) bool {
			return d.EncryptionAtRestOptions != nil && d.EncryptionAtRestOptions.Enabled != nil && *d.EncryptionAtRestOptions.Enabled
		},
		buildInput: func(name string) *elasticsearchservice.UpdateElasticsearchDomainConfigInput {
			return &elasticsearchservice.UpdateElasticsearchDomainConfigInput{
				DomainName:              aws.String(name),
				EncryptionAtRestOptions: &estypes.EncryptionAtRestOptions{Enabled: aws.Bool(true)},
			}
		},
		clients: clients,
	}
}

// newElasticsearchNodeToNodeEncryptionFix fixes elasticsearch-node-to-node-encryption-check.
func newElasticsearchNodeToNodeEncryptionFix(clients *awsdata.Clients) *elasticsearchFix {
	return &elasticsearchFix{
		checkID:     "elasticsearch-node-to-node-encryption-check",
		description: "Enable node-to-node encryption for Elasticsearch domain",
		severity:    fix.SeverityHigh,
		alreadyOK: func(d estypes.ElasticsearchDomainStatus) bool {
			return d.NodeToNodeEncryptionOptions != nil && d.NodeToNodeEncryptionOptions.Enabled != nil && *d.NodeToNodeEncryptionOptions.Enabled
		},
		buildInput: func(name string) *elasticsearchservice.UpdateElasticsearchDomainConfigInput {
			return &elasticsearchservice.UpdateElasticsearchDomainConfigInput{
				DomainName:                  aws.String(name),
				NodeToNodeEncryptionOptions: &estypes.NodeToNodeEncryptionOptions{Enabled: aws.Bool(true)},
			}
		},
		clients: clients,
	}
}
