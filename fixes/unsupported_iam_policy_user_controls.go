package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch18(d *awsdata.Data) {
	_ = d

	checks := []struct {
		id     string
		reason string
	}{
		{id: "iam-user-mfa-enabled", reason: "requires user-by-user MFA enrollment and verification"},
		{id: "iam-user-unused-credentials-check", reason: "requires credential-age review and rotation decisions"},
		{id: "iam-user-no-policies-check", reason: "requires policy migration to groups/roles per access model"},
		{id: "iam-user-group-membership-check", reason: "requires validating least-privilege group assignments"},
		{id: "iam-role-managed-policy-check", reason: "requires selecting approved managed policies for each role"},
		{id: "iam-policy-no-statements-with-admin-access", reason: "requires least-privilege redesign of admin statements"},
		{id: "iam-policy-no-statements-with-full-access", reason: "requires narrowing wildcard actions/resources safely"},
		{id: "iam-policy-blacklisted-check", reason: "requires policy refactor to remove prohibited IAM actions"},
		{id: "iam-inline-policy-blocked-kms-actions", reason: "requires inline policy edits to remove blocked KMS actions"},
		{id: "iam-customer-policy-blocked-kms-actions", reason: "requires customer-managed policy updates for blocked KMS actions"},
	}

	for _, c := range checks {
		if fix.Lookup(c.id) == nil {
			fix.Register(&unsupportedFix{checkID: c.id, reason: c.reason})
		}
	}
}
