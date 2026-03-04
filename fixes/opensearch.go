package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opentypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

// ── opensearch-audit-logging-enabled ─────────────────────────────────────────

type opensearchAuditLoggingFix struct{ clients *awsdata.Clients }

func (f *opensearchAuditLoggingFix) CheckID() string { return "opensearch-audit-logging-enabled" }
func (f *opensearchAuditLoggingFix) Description() string {
	return "Enable audit logging on OpenSearch domain"
}
func (f *opensearchAuditLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *opensearchAuditLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *opensearchAuditLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.OpenSearch.DescribeDomain(fctx.Ctx, &opensearch.DescribeDomainInput{
		DomainName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe domain: " + err.Error()
		return base
	}
	if out.DomainStatus != nil && out.DomainStatus.LogPublishingOptions != nil {
		if opt, ok := out.DomainStatus.LogPublishingOptions[string(opentypes.LogTypeAuditLogs)]; ok {
			if opt.Enabled != nil && *opt.Enabled {
				base.Status = fix.FixSkipped
				base.Message = "audit logging already enabled"
				return base
			}
		}
	}

	region := f.clients.CloudWatchLogs.Options().Region
	callerOut, err := f.clients.STS.GetCallerIdentity(fctx.Ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get caller identity: " + err.Error()
		return base
	}
	account := aws.ToString(callerOut.Account)

	logGroupName := "/aws/opensearch/domains/" + resourceID + "/audit-logs"
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable audit logging on OpenSearch domain %s", resourceID),
		}
		return base
	}

	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	// OpenSearch requires a resource-based policy on the log group
	policyName := "opensearch-audit-logs-" + resourceID
	policyDoc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"es.amazonaws.com"},"Action":["logs:PutLogEvents","logs:CreateLogStream"],"Resource":"%s:*","Condition":{"StringEquals":{"aws:SourceAccount":"%s"}}}]}`,
		logGroupArn, account)
	_, prErr := f.clients.CloudWatchLogs.PutResourcePolicy(fctx.Ctx, &cloudwatchlogs.PutResourcePolicyInput{
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(policyDoc),
	})
	if prErr != nil {
		base.Status = fix.FixFailed
		base.Message = "put CW log group resource policy: " + prErr.Error()
		return base
	}

	_, err = f.clients.OpenSearch.UpdateDomainConfig(fctx.Ctx, &opensearch.UpdateDomainConfigInput{
		DomainName: aws.String(resourceID),
		LogPublishingOptions: map[string]opentypes.LogPublishingOption{
			string(opentypes.LogTypeAuditLogs): {
				Enabled:                 aws.Bool(true),
				CloudWatchLogsLogGroupArn: aws.String(logGroupArn),
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update domain config: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("ensured log group %s exists with OpenSearch resource policy", logGroupName),
		fmt.Sprintf("enabled audit logging on OpenSearch domain %s", resourceID),
	}
	base.Status = fix.FixApplied
	return base
}
