package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opentypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

// opensearchFix applies a single UpdateDomainConfig change to an OpenSearch domain.
// A parameterised base handles the idempotency check and DryRun logic so each
// concrete fix only supplies the check/skip predicate and the config to apply.
type opensearchFix struct {
	checkID     string
	description string
	severity    fix.SeverityLevel
	// alreadyOK returns true when the domain config already satisfies the check.
	alreadyOK func(dom opentypes.DomainStatus) bool
	// buildInput returns the UpdateDomainConfigInput to apply (Name already set by caller).
	buildInput func(domainName string) *opensearch.UpdateDomainConfigInput
	clients    *awsdata.Clients
}

func (f *opensearchFix) CheckID() string          { return f.checkID }
func (f *opensearchFix) Description() string      { return f.description }
func (f *opensearchFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *opensearchFix) Severity() fix.SeverityLevel { return f.severity }

func (f *opensearchFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.OpenSearch.DescribeDomain(fctx.Ctx, &opensearch.DescribeDomainInput{
		DomainName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe domain: " + err.Error()
		return base
	}
	if out.DomainStatus != nil && f.alreadyOK(*out.DomainStatus) {
		base.Status = fix.FixSkipped
		base.Message = f.checkID + " already satisfied"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would apply %s fix on domain %s", f.checkID, resourceID)}
		return base
	}

	input := f.buildInput(resourceID)
	_, err = f.clients.OpenSearch.UpdateDomainConfig(fctx.Ctx, input)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update domain config: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("applied %s fix on domain %s", f.checkID, resourceID)}
	base.Status = fix.FixApplied
	return base
}

// newOpenSearchEncryptionAtRestFix fixes opensearch-encrypted-at-rest.
func newOpenSearchEncryptionAtRestFix(clients *awsdata.Clients) *opensearchFix {
	return &opensearchFix{
		checkID:     "opensearch-encrypted-at-rest",
		description: "Enable encryption at rest for OpenSearch domain",
		severity:    fix.SeverityHigh,
		alreadyOK: func(d opentypes.DomainStatus) bool {
			return d.EncryptionAtRestOptions != nil && d.EncryptionAtRestOptions.Enabled != nil && *d.EncryptionAtRestOptions.Enabled
		},
		buildInput: func(name string) *opensearch.UpdateDomainConfigInput {
			return &opensearch.UpdateDomainConfigInput{
				DomainName:           aws.String(name),
				EncryptionAtRestOptions: &opentypes.EncryptionAtRestOptions{Enabled: aws.Bool(true)},
			}
		},
		clients: clients,
	}
}

// newOpenSearchNodeToNodeEncryptionFix fixes opensearch-node-to-node-encryption-check.
func newOpenSearchNodeToNodeEncryptionFix(clients *awsdata.Clients) *opensearchFix {
	return &opensearchFix{
		checkID:     "opensearch-node-to-node-encryption-check",
		description: "Enable node-to-node encryption for OpenSearch domain",
		severity:    fix.SeverityHigh,
		alreadyOK: func(d opentypes.DomainStatus) bool {
			return d.NodeToNodeEncryptionOptions != nil && d.NodeToNodeEncryptionOptions.Enabled != nil && *d.NodeToNodeEncryptionOptions.Enabled
		},
		buildInput: func(name string) *opensearch.UpdateDomainConfigInput {
			return &opensearch.UpdateDomainConfigInput{
				DomainName:                  aws.String(name),
				NodeToNodeEncryptionOptions: &opentypes.NodeToNodeEncryptionOptions{Enabled: aws.Bool(true)},
			}
		},
		clients: clients,
	}
}

// newOpenSearchHTTPSFix fixes opensearch-https-required.
func newOpenSearchHTTPSFix(clients *awsdata.Clients) *opensearchFix {
	return &opensearchFix{
		checkID:     "opensearch-https-required",
		description: "Enforce HTTPS on OpenSearch domain endpoint",
		severity:    fix.SeverityHigh,
		alreadyOK: func(d opentypes.DomainStatus) bool {
			return d.DomainEndpointOptions != nil && d.DomainEndpointOptions.EnforceHTTPS != nil && *d.DomainEndpointOptions.EnforceHTTPS
		},
		buildInput: func(name string) *opensearch.UpdateDomainConfigInput {
			return &opensearch.UpdateDomainConfigInput{
				DomainName:            aws.String(name),
				DomainEndpointOptions: &opentypes.DomainEndpointOptions{EnforceHTTPS: aws.Bool(true)},
			}
		},
		clients: clients,
	}
}
