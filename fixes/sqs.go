package fixes

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// ── shared IAM-policy helpers (used by sqs.go and sns.go) ────────────────────

// removePublicAllowStatements removes Allow statements with a wildcard principal
// from policyJSON. Returns ("", false, nil) if no statements are public.
func removePublicAllowStatements(policyJSON string) (newJSON string, changed bool, err error) {
	if strings.TrimSpace(policyJSON) == "" {
		return "", false, nil
	}
	var doc struct {
		Version   string            `json:"Version,omitempty"`
		Id        string            `json:"Id,omitempty"`
		Statement []json.RawMessage `json:"Statement"`
	}
	if err = json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return "", false, fmt.Errorf("parse policy: %w", err)
	}
	var kept []json.RawMessage
	for _, raw := range doc.Statement {
		var stmt struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
		}
		if json.Unmarshal(raw, &stmt) == nil &&
			strings.EqualFold(strings.TrimSpace(stmt.Effect), "Allow") &&
			policyPrincipalIsWildcard(stmt.Principal) {
			changed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !changed {
		return "", false, nil
	}
	doc.Statement = kept
	b, err := json.Marshal(doc)
	if err != nil {
		return "", false, fmt.Errorf("marshal policy: %w", err)
	}
	return string(b), true, nil
}

// removePublicWildcardActionStatements removes Allow statements with a wildcard
// principal AND a wildcard or full-service action (SQS:*, *) from policyJSON.
func removePublicWildcardActionStatements(policyJSON string) (newJSON string, changed bool, err error) {
	if strings.TrimSpace(policyJSON) == "" {
		return "", false, nil
	}
	var doc struct {
		Version   string            `json:"Version,omitempty"`
		Id        string            `json:"Id,omitempty"`
		Statement []json.RawMessage `json:"Statement"`
	}
	if err = json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return "", false, fmt.Errorf("parse policy: %w", err)
	}
	var kept []json.RawMessage
	for _, raw := range doc.Statement {
		var stmt struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
		}
		if json.Unmarshal(raw, &stmt) == nil &&
			strings.EqualFold(strings.TrimSpace(stmt.Effect), "Allow") &&
			policyPrincipalIsWildcard(stmt.Principal) &&
			policyActionHasWildcard(stmt.Action) {
			changed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !changed {
		return "", false, nil
	}
	doc.Statement = kept
	b, err := json.Marshal(doc)
	if err != nil {
		return "", false, fmt.Errorf("marshal policy: %w", err)
	}
	return string(b), true, nil
}

func policyPrincipalIsWildcard(p interface{}) bool {
	switch v := p.(type) {
	case string:
		return strings.TrimSpace(v) == "*"
	case map[string]interface{}:
		for _, val := range v {
			switch typed := val.(type) {
			case string:
				if strings.TrimSpace(typed) == "*" {
					return true
				}
			case []interface{}:
				for _, item := range typed {
					if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func policyActionHasWildcard(action interface{}) bool {
	var actions []string
	switch a := action.(type) {
	case string:
		actions = []string{a}
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok {
				actions = append(actions, s)
			}
		}
	}
	for _, a := range actions {
		lower := strings.ToLower(strings.TrimSpace(a))
		if lower == "*" || lower == "sqs:*" {
			return true
		}
	}
	return false
}

// ── sqs-queue-no-public-access ────────────────────────────────────────────────

type sqsNoPublicAccessFix struct{ clients *awsdata.Clients }

func (f *sqsNoPublicAccessFix) CheckID() string { return "sqs-queue-no-public-access" }
func (f *sqsNoPublicAccessFix) Description() string {
	return "Remove public Allow statements from SQS queue policy"
}
func (f *sqsNoPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *sqsNoPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *sqsNoPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.SQS.GetQueueAttributes(fctx.Ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(resourceID),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get queue attributes: " + err.Error()
		return base
	}

	currentPolicy := attrOut.Attributes["Policy"]
	newPolicy, changed, err := removePublicAllowStatements(currentPolicy)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "parse queue policy: " + err.Error()
		return base
	}
	if !changed {
		base.Status = fix.FixSkipped
		base.Message = "SQS queue policy has no public Allow statements"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public Allow statements from SQS queue %s policy", resourceID)}
		return base
	}

	_, err = f.clients.SQS.SetQueueAttributes(fctx.Ctx, &sqs.SetQueueAttributesInput{
		QueueUrl:   aws.String(resourceID),
		Attributes: map[string]string{"Policy": newPolicy},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set queue attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public Allow statements from SQS queue %s policy", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── sqs-queue-policy-full-access-check ────────────────────────────────────────

type sqsNoFullAccessFix struct{ clients *awsdata.Clients }

func (f *sqsNoFullAccessFix) CheckID() string { return "sqs-queue-policy-full-access-check" }
func (f *sqsNoFullAccessFix) Description() string {
	return "Remove public wildcard (SQS:*) Allow statements from SQS queue policy"
}
func (f *sqsNoFullAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *sqsNoFullAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *sqsNoFullAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.SQS.GetQueueAttributes(fctx.Ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(resourceID),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get queue attributes: " + err.Error()
		return base
	}

	currentPolicy := attrOut.Attributes["Policy"]
	newPolicy, changed, err := removePublicWildcardActionStatements(currentPolicy)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "parse queue policy: " + err.Error()
		return base
	}
	if !changed {
		base.Status = fix.FixSkipped
		base.Message = "SQS queue policy has no public wildcard Allow statements"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public SQS:* Allow statements from SQS queue %s policy", resourceID)}
		return base
	}

	_, err = f.clients.SQS.SetQueueAttributes(fctx.Ctx, &sqs.SetQueueAttributesInput{
		QueueUrl:   aws.String(resourceID),
		Attributes: map[string]string{"Policy": newPolicy},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set queue attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public SQS:* Allow statements from SQS queue %s policy", resourceID)}
	base.Status = fix.FixApplied
	return base
}
