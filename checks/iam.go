package checks

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// credentialReportRow represents a parsed row from the IAM credential report CSV.
type credentialReportRow struct {
	User                  string
	ARN                   string
	PasswordEnabled       string
	MFAActive             string
	AccessKey1Active      string
	AccessKey1LastRotated string
	AccessKey2Active      string
	AccessKey2LastRotated string
	PasswordLastUsed      string
	AccessKey1LastUsed    string
	AccessKey2LastUsed    string
}

func parseCredentialReport(data []byte) ([]credentialReportRow, error) {
	r := csv.NewReader(bytes.NewReader(data))
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing credential report CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, nil
	}
	header := records[0]
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[h] = i
	}
	getCol := func(row []string, name string) string {
		if idx, ok := colIdx[name]; ok && idx < len(row) {
			return row[idx]
		}
		return ""
	}

	var rows []credentialReportRow
	for _, rec := range records[1:] {
		rows = append(rows, credentialReportRow{
			User:                  getCol(rec, "user"),
			ARN:                   getCol(rec, "arn"),
			PasswordEnabled:       getCol(rec, "password_enabled"),
			MFAActive:             getCol(rec, "mfa_active"),
			AccessKey1Active:      getCol(rec, "access_key_1_active"),
			AccessKey1LastRotated: getCol(rec, "access_key_1_last_rotated"),
			AccessKey2Active:      getCol(rec, "access_key_2_active"),
			AccessKey2LastRotated: getCol(rec, "access_key_2_last_rotated"),
			PasswordLastUsed:      getCol(rec, "password_last_used"),
			AccessKey1LastUsed:    getCol(rec, "access_key_1_last_used_date"),
			AccessKey2LastUsed:    getCol(rec, "access_key_2_last_used_date"),
		})
	}
	return rows, nil
}

// policyDocument is a minimal representation of an IAM policy document.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

func (s *policyStatement) actions() []string {
	return toStringSlice(s.Action)
}

func (s *policyStatement) resources() []string {
	return toStringSlice(s.Resource)
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var out []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func decodePolicyDocument(encoded string) (*policyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		decoded = encoded
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func hasAdminAccess(doc *policyDocument) bool {
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := stmt.actions()
		resources := stmt.resources()
		allActions := false
		allResources := false
		for _, a := range actions {
			if a == "*" {
				allActions = true
				break
			}
		}
		for _, r := range resources {
			if r == "*" {
				allResources = true
				break
			}
		}
		if allActions && allResources {
			return true
		}
	}
	return false
}

func hasFullAccess(doc *policyDocument) bool {
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		for _, a := range stmt.actions() {
			if strings.HasSuffix(a, ":*") || a == "*" {
				return true
			}
		}
	}
	return false
}

func hasBlockedKMSActions(doc *policyDocument) bool {
	blockedPatterns := []string{
		"kms:decrypt",
		"kms:reencrypt*",
		"kms:*",
	}
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		resources := stmt.resources()
		hasWildcard := false
		for _, r := range resources {
			if r == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			continue
		}
		for _, a := range stmt.actions() {
			action := strings.ToLower(strings.TrimSpace(a))
			if action == "*" {
				return true
			}
			for _, pattern := range blockedPatterns {
				if iamActionMatchesPattern(action, pattern) {
					return true
				}
			}
		}
	}
	return false
}

func iamActionMatchesPattern(action, pattern string) bool {
	if action == pattern {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	ok, err := path.Match(pattern, action)
	return err == nil && ok
}

func isKeyOlderThan90Days(dateStr string) bool {
	if dateStr == "" || dateStr == "N/A" || dateStr == "not_supported" {
		return false
	}
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05+00:00", dateStr)
		if err != nil {
			return true // can't parse, treat as too old
		}
	}
	return time.Since(t) > 90*24*time.Hour
}

func isCredentialUnused(dateStr string, days int) bool {
	if dateStr == "" || dateStr == "N/A" || dateStr == "no_information" || dateStr == "not_supported" {
		return false
	}
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05+00:00", dateStr)
		if err != nil {
			return true
		}
	}
	return time.Since(t) > time.Duration(days)*24*time.Hour
}

func iamParseCSV(value string) []string {
	items := strings.Split(value, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func iamListAllAttachedUserPolicyARNs(d *awsdata.Data, userName *string) (map[string]bool, error) {
	out := make(map[string]bool)
	var marker *string
	for {
		resp, err := d.Clients.IAM.ListAttachedUserPolicies(d.Ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: userName,
			Marker:   marker,
		})
		if err != nil {
			return nil, err
		}
		for _, policy := range resp.AttachedPolicies {
			if policy.PolicyArn != nil {
				out[*policy.PolicyArn] = true
			}
		}
		if !resp.IsTruncated || resp.Marker == nil || *resp.Marker == "" {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

func iamListAllAttachedRolePolicyARNs(d *awsdata.Data, roleName *string) (map[string]bool, error) {
	out := make(map[string]bool)
	var marker *string
	for {
		resp, err := d.Clients.IAM.ListAttachedRolePolicies(d.Ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: roleName,
			Marker:   marker,
		})
		if err != nil {
			return nil, err
		}
		for _, policy := range resp.AttachedPolicies {
			if policy.PolicyArn != nil {
				out[*policy.PolicyArn] = true
			}
		}
		if !resp.IsTruncated || resp.Marker == nil || *resp.Marker == "" {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

func iamListAllAttachedGroupPolicyARNs(d *awsdata.Data, groupName *string) (map[string]bool, error) {
	out := make(map[string]bool)
	var marker *string
	for {
		resp, err := d.Clients.IAM.ListAttachedGroupPolicies(d.Ctx, &iam.ListAttachedGroupPoliciesInput{
			GroupName: groupName,
			Marker:    marker,
		})
		if err != nil {
			return nil, err
		}
		for _, policy := range resp.AttachedPolicies {
			if policy.PolicyArn != nil {
				out[*policy.PolicyArn] = true
			}
		}
		if !resp.IsTruncated || resp.Marker == nil || *resp.Marker == "" {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

func iamUserHasInlinePolicies(d *awsdata.Data, userName *string) (bool, error) {
	var marker *string
	for {
		resp, err := d.Clients.IAM.ListUserPolicies(d.Ctx, &iam.ListUserPoliciesInput{
			UserName: userName,
			Marker:   marker,
		})
		if err != nil {
			return false, err
		}
		if len(resp.PolicyNames) > 0 {
			return true, nil
		}
		if !resp.IsTruncated || resp.Marker == nil || *resp.Marker == "" {
			break
		}
		marker = resp.Marker
	}
	return false, nil
}

// RegisterIAMChecks registers all IAM-related best-practice checks.
func RegisterIAMChecks(d *awsdata.Data) {
	// ---------------------------------------------------------------
	// access-keys-rotated
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"access-keys-rotated",
		"This rule checks rotation for access keys.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			report, err := d.IAMCredentialReport.Get()
			if err != nil {
				return nil, err
			}
			rows, err := parseCredentialReport(report)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, row := range rows {
				if row.User == "<root_account>" {
					continue
				}
				passing := true
				detail := "Access keys are rotated within 90 days"
				if row.AccessKey1Active == "true" && isKeyOlderThan90Days(row.AccessKey1LastRotated) {
					passing = false
					detail = "Access key 1 not rotated within 90 days"
				}
				if row.AccessKey2Active == "true" && isKeyOlderThan90Days(row.AccessKey2LastRotated) {
					passing = false
					detail = "Access key 2 not rotated within 90 days"
				}
				res = append(res, ConfigResource{ID: row.User, Passing: passing, Detail: detail})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-customer-policy-blocked-kms-actions
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-customer-policy-blocked-kms-actions",
		"This rule checks IAM customer policy blocked KMS actions.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.IAMPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range policies {
				policyArn := ""
				policyName := ""
				if p.Arn != nil {
					policyArn = *p.Arn
				}
				if p.PolicyName != nil {
					policyName = *p.PolicyName
				}
				id := policyName
				if id == "" {
					id = policyArn
				}
				out, err := d.Clients.IAM.GetPolicyVersion(d.Ctx, &iam.GetPolicyVersionInput{
					PolicyArn: p.Arn,
					VersionId: p.DefaultVersionId,
				})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Error fetching policy version"})
					continue
				}
				if out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "No policy document"})
					continue
				}
				doc, err := decodePolicyDocument(*out.PolicyVersion.Document)
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Error decoding policy document"})
					continue
				}
				if hasBlockedKMSActions(doc) {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Policy allows blocked KMS actions on all resources"})
				} else {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Policy does not allow blocked KMS actions"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-external-access-analyzer-enabled
	// ---------------------------------------------------------------
	checker.Register(SingleCheck(
		"iam-external-access-analyzer-enabled",
		"This rule checks enabled state for IAM external access analyzer.",
		"IAM", d,
		func(d *awsdata.Data) (bool, string, error) {
			out, err := d.Clients.AccessAnalyzer.ListAnalyzers(d.Ctx, &accessanalyzer.ListAnalyzersInput{
				Type: accessanalyzertypes.TypeAccount,
			})
			if err != nil {
				return false, "", err
			}
			for _, a := range out.Analyzers {
				if a.Status == accessanalyzertypes.AnalyzerStatusActive {
					name := ""
					if a.Name != nil {
						name = *a.Name
					}
					return true, fmt.Sprintf("External access analyzer '%s' is active", name), nil
				}
			}
			return false, "No active external access analyzer found", nil
		},
	))

	// ---------------------------------------------------------------
	// iam-group-has-users-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-group-has-users-check",
		"This rule checks configuration for IAM group has users.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.IAMGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				name := ""
				if g.GroupName != nil {
					name = *g.GroupName
				}
				out, err := d.Clients.IAM.GetGroup(d.Ctx, &iam.GetGroupInput{GroupName: g.GroupName})
				if err != nil {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Error fetching group members"})
					continue
				}
				if len(out.Users) > 0 {
					res = append(res, ConfigResource{ID: name, Passing: true, Detail: "Group has users"})
				} else {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Group has no users"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-inline-policy-blocked-kms-actions
	// ---------------------------------------------------------------
	checker.Register(&BaseCheck{
		CheckID: "iam-inline-policy-blocked-kms-actions",
		Desc:    "This rule checks IAM inline policy blocked KMS actions.",
		Svc:     "IAM",
		RunFunc: func() []checker.Result {
			var results []checker.Result

			// Check users
			users, err := d.IAMUsers.Get()
			if err != nil {
				return []checker.Result{{CheckID: "iam-inline-policy-blocked-kms-actions", Status: checker.StatusError, Message: err.Error()}}
			}
			for _, u := range users {
				userName := ""
				if u.UserName != nil {
					userName = *u.UserName
				}
				listOut, err := d.Clients.IAM.ListUserPolicies(d.Ctx, &iam.ListUserPoliciesInput{UserName: u.UserName})
				if err != nil {
					continue
				}
				for _, pName := range listOut.PolicyNames {
					polOut, err := d.Clients.IAM.GetUserPolicy(d.Ctx, &iam.GetUserPolicyInput{UserName: u.UserName, PolicyName: &pName})
					if err != nil || polOut.PolicyDocument == nil {
						continue
					}
					doc, err := decodePolicyDocument(*polOut.PolicyDocument)
					if err != nil {
						continue
					}
					id := fmt.Sprintf("user/%s/%s", userName, pName)
					if hasBlockedKMSActions(doc) {
						results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusFail, Message: "Inline policy allows blocked KMS actions"})
					} else {
						results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusPass, Message: "Inline policy does not allow blocked KMS actions"})
					}
				}
			}

			// Check roles
			roles, err := d.IAMRoles.Get()
			if err == nil {
				for _, r := range roles {
					roleName := ""
					if r.RoleName != nil {
						roleName = *r.RoleName
					}
					listOut, err := d.Clients.IAM.ListRolePolicies(d.Ctx, &iam.ListRolePoliciesInput{RoleName: r.RoleName})
					if err != nil {
						continue
					}
					for _, pName := range listOut.PolicyNames {
						polOut, err := d.Clients.IAM.GetRolePolicy(d.Ctx, &iam.GetRolePolicyInput{RoleName: r.RoleName, PolicyName: &pName})
						if err != nil || polOut.PolicyDocument == nil {
							continue
						}
						doc, err := decodePolicyDocument(*polOut.PolicyDocument)
						if err != nil {
							continue
						}
						id := fmt.Sprintf("role/%s/%s", roleName, pName)
						if hasBlockedKMSActions(doc) {
							results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusFail, Message: "Inline policy allows blocked KMS actions"})
						} else {
							results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusPass, Message: "Inline policy does not allow blocked KMS actions"})
						}
					}
				}
			}

			// Check groups
			groups, err := d.IAMGroups.Get()
			if err == nil {
				for _, g := range groups {
					groupName := ""
					if g.GroupName != nil {
						groupName = *g.GroupName
					}
					listOut, err := d.Clients.IAM.ListGroupPolicies(d.Ctx, &iam.ListGroupPoliciesInput{GroupName: g.GroupName})
					if err != nil {
						continue
					}
					for _, pName := range listOut.PolicyNames {
						polOut, err := d.Clients.IAM.GetGroupPolicy(d.Ctx, &iam.GetGroupPolicyInput{GroupName: g.GroupName, PolicyName: &pName})
						if err != nil || polOut.PolicyDocument == nil {
							continue
						}
						doc, err := decodePolicyDocument(*polOut.PolicyDocument)
						if err != nil {
							continue
						}
						id := fmt.Sprintf("group/%s/%s", groupName, pName)
						if hasBlockedKMSActions(doc) {
							results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusFail, Message: "Inline policy allows blocked KMS actions"})
						} else {
							results = append(results, checker.Result{CheckID: "iam-inline-policy-blocked-kms-actions", ResourceID: id, Status: checker.StatusPass, Message: "Inline policy does not allow blocked KMS actions"})
						}
					}
				}
			}

			if len(results) == 0 {
				return []checker.Result{{CheckID: "iam-inline-policy-blocked-kms-actions", Status: checker.StatusSkip, Message: "No inline policies found"}}
			}
			return results
		},
	})

	// ---------------------------------------------------------------
	// iam-no-inline-policy-check
	// ---------------------------------------------------------------
	checker.Register(&BaseCheck{
		CheckID: "iam-no-inline-policy-check",
		Desc:    "This rule checks configuration for IAM no inline policy.",
		Svc:     "IAM",
		RunFunc: func() []checker.Result {
			var results []checker.Result

			users, err := d.IAMUsers.Get()
			if err != nil {
				return []checker.Result{{CheckID: "iam-no-inline-policy-check", Status: checker.StatusError, Message: err.Error()}}
			}
			for _, u := range users {
				userName := ""
				if u.UserName != nil {
					userName = *u.UserName
				}
				listOut, err := d.Clients.IAM.ListUserPolicies(d.Ctx, &iam.ListUserPoliciesInput{UserName: u.UserName})
				if err != nil {
					continue
				}
				if len(listOut.PolicyNames) > 0 {
					results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "user/" + userName, Status: checker.StatusFail, Message: "User has inline policies"})
				} else {
					results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "user/" + userName, Status: checker.StatusPass, Message: "User has no inline policies"})
				}
			}

			roles, err := d.IAMRoles.Get()
			if err == nil {
				for _, r := range roles {
					roleName := ""
					if r.RoleName != nil {
						roleName = *r.RoleName
					}
					listOut, err := d.Clients.IAM.ListRolePolicies(d.Ctx, &iam.ListRolePoliciesInput{RoleName: r.RoleName})
					if err != nil {
						continue
					}
					if len(listOut.PolicyNames) > 0 {
						results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "role/" + roleName, Status: checker.StatusFail, Message: "Role has inline policies"})
					} else {
						results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "role/" + roleName, Status: checker.StatusPass, Message: "Role has no inline policies"})
					}
				}
			}

			groups, err := d.IAMGroups.Get()
			if err == nil {
				for _, g := range groups {
					groupName := ""
					if g.GroupName != nil {
						groupName = *g.GroupName
					}
					listOut, err := d.Clients.IAM.ListGroupPolicies(d.Ctx, &iam.ListGroupPoliciesInput{GroupName: g.GroupName})
					if err != nil {
						continue
					}
					if len(listOut.PolicyNames) > 0 {
						results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "group/" + groupName, Status: checker.StatusFail, Message: "Group has inline policies"})
					} else {
						results = append(results, checker.Result{CheckID: "iam-no-inline-policy-check", ResourceID: "group/" + groupName, Status: checker.StatusPass, Message: "Group has no inline policies"})
					}
				}
			}

			if len(results) == 0 {
				return []checker.Result{{CheckID: "iam-no-inline-policy-check", Status: checker.StatusSkip, Message: "No IAM entities found"}}
			}
			return results
		},
	})

	// ---------------------------------------------------------------
	// iam-oidc-provider-tagged
	// ---------------------------------------------------------------
	checker.Register(TaggedCheck(
		"iam-oidc-provider-tagged",
		"This rule checks tagging for IAM oidc provider exist.",
		"IAM", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			arns, err := d.IAMOIDCProviders.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, arn := range arns {
				arnCopy := arn
				out, err := d.Clients.IAM.GetOpenIDConnectProvider(d.Ctx, &iam.GetOpenIDConnectProviderInput{
					OpenIDConnectProviderArn: &arnCopy,
				})
				if err != nil {
					res = append(res, TaggedResource{ID: arn, Tags: nil})
					continue
				}
				tags := make(map[string]string)
				for _, t := range out.Tags {
					if t.Key != nil && t.Value != nil {
						tags[*t.Key] = *t.Value
					}
				}
				res = append(res, TaggedResource{ID: arn, Tags: tags})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-password-policy
	// ---------------------------------------------------------------
	checker.Register(SingleCheck(
		"iam-password-policy",
		"This rule checks IAM password policy.",
		"IAM", d,
		func(d *awsdata.Data) (bool, string, error) {
			pp, err := d.IAMAccountPasswordPolicy.Get()
			if err != nil {
				return false, "No password policy configured", nil
			}
			if pp == nil {
				return false, "No password policy configured", nil
			}
			var issues []string
			if pp.MinimumPasswordLength == nil || *pp.MinimumPasswordLength < 14 {
				issues = append(issues, "minimum length < 14")
			}
			if !pp.RequireUppercaseCharacters {
				issues = append(issues, "uppercase not required")
			}
			if !pp.RequireLowercaseCharacters {
				issues = append(issues, "lowercase not required")
			}
			if !pp.RequireNumbers {
				issues = append(issues, "numbers not required")
			}
			if !pp.RequireSymbols {
				issues = append(issues, "symbols not required")
			}
			if pp.PasswordReusePrevention == nil || *pp.PasswordReusePrevention < 24 {
				issues = append(issues, "password reuse prevention < 24")
			}
			if pp.MaxPasswordAge == nil || *pp.MaxPasswordAge <= 0 || *pp.MaxPasswordAge > 90 {
				issues = append(issues, "max password age not set to 1-90 days")
			}
			if len(issues) > 0 {
				return false, "Password policy issues: " + strings.Join(issues, ", "), nil
			}
			return true, "Password policy meets requirements", nil
		},
	))

	// ---------------------------------------------------------------
	// iam-policy-blacklisted-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-policy-blacklisted-check",
		"This rule checks configuration for IAM policy blacklisted.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			blacklisted := map[string]bool{
				"arn:aws:iam::aws:policy/AdministratorAccess": true,
			}
			var res []ConfigResource

			users, err := d.IAMUsers.Get()
			if err != nil {
				return nil, err
			}
			for _, u := range users {
				userName := ""
				if u.UserName != nil {
					userName = *u.UserName
				}
				attached, err := iamListAllAttachedUserPolicyARNs(d, u.UserName)
				if err != nil {
					continue
				}
				found := false
				for policyARN := range attached {
					if blacklisted[policyARN] {
						found = true
						break
					}
				}
				if found {
					res = append(res, ConfigResource{ID: "user/" + userName, Passing: false, Detail: "Blacklisted policy attached"})
				} else {
					res = append(res, ConfigResource{ID: "user/" + userName, Passing: true, Detail: "No blacklisted policies"})
				}
			}

			roles, err := d.IAMRoles.Get()
			if err == nil {
				for _, r := range roles {
					roleName := ""
					if r.RoleName != nil {
						roleName = *r.RoleName
					}
					attached, err := iamListAllAttachedRolePolicyARNs(d, r.RoleName)
					if err != nil {
						continue
					}
					found := false
					for policyARN := range attached {
						if blacklisted[policyARN] {
							found = true
							break
						}
					}
					if found {
						res = append(res, ConfigResource{ID: "role/" + roleName, Passing: false, Detail: "Blacklisted policy attached"})
					} else {
						res = append(res, ConfigResource{ID: "role/" + roleName, Passing: true, Detail: "No blacklisted policies"})
					}
				}
			}

			groups, err := d.IAMGroups.Get()
			if err == nil {
				for _, g := range groups {
					groupName := ""
					if g.GroupName != nil {
						groupName = *g.GroupName
					}
					attached, err := iamListAllAttachedGroupPolicyARNs(d, g.GroupName)
					if err != nil {
						continue
					}
					found := false
					for policyARN := range attached {
						if blacklisted[policyARN] {
							found = true
							break
						}
					}
					if found {
						res = append(res, ConfigResource{ID: "group/" + groupName, Passing: false, Detail: "Blacklisted policy attached"})
					} else {
						res = append(res, ConfigResource{ID: "group/" + groupName, Passing: true, Detail: "No blacklisted policies"})
					}
				}
			}

			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-policy-in-use
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-policy-in-use",
		"This rule checks IAM policy in use.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.IAMPolicies.Get()
			if err != nil {
				return nil, err
			}
			requiredPolicyARNs := iamParseCSV(os.Getenv("BPTOOLS_REQUIRED_POLICY_ARNS"))
			requiredPolicyNames := iamParseCSV(os.Getenv("BPTOOLS_REQUIRED_POLICY_NAMES"))
			if len(requiredPolicyARNs) == 0 && len(requiredPolicyNames) == 0 {
				return []ConfigResource{{ID: "account", Passing: true, Detail: "No required policies configured; default not-applicable behavior"}}, nil
			}
			byARN := make(map[string]iamtypes.Policy)
			byName := make(map[string]iamtypes.Policy)
			for _, p := range policies {
				if p.Arn != nil {
					byARN[*p.Arn] = p
				}
				if p.PolicyName != nil {
					byName[*p.PolicyName] = p
				}
			}
			var res []ConfigResource
			for _, arn := range requiredPolicyARNs {
				p, ok := byARN[arn]
				if !ok {
					res = append(res, ConfigResource{ID: arn, Passing: false, Detail: "Required policy not found"})
					continue
				}
				attached := p.AttachmentCount != nil && *p.AttachmentCount > 0
				res = append(res, ConfigResource{ID: arn, Passing: attached, Detail: fmt.Sprintf("Required policy attached: %v", attached)})
			}
			for _, name := range requiredPolicyNames {
				p, ok := byName[name]
				if !ok {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Required policy not found"})
					continue
				}
				attached := p.AttachmentCount != nil && *p.AttachmentCount > 0
				res = append(res, ConfigResource{ID: name, Passing: attached, Detail: fmt.Sprintf("Required policy attached: %v", attached)})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-policy-no-statements-with-admin-access
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-policy-no-statements-with-admin-access",
		"This rule checks IAM policy no statements with admin access.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.IAMPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range policies {
				id := ""
				if p.PolicyName != nil {
					id = *p.PolicyName
				} else if p.Arn != nil {
					id = *p.Arn
				}
				out, err := d.Clients.IAM.GetPolicyVersion(d.Ctx, &iam.GetPolicyVersionInput{
					PolicyArn: p.Arn,
					VersionId: p.DefaultVersionId,
				})
				if err != nil || out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Could not retrieve policy document"})
					continue
				}
				doc, err := decodePolicyDocument(*out.PolicyVersion.Document)
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Could not decode policy document"})
					continue
				}
				if hasAdminAccess(doc) {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Policy has statements granting admin access"})
				} else {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Policy has no admin access statements"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-policy-no-statements-with-full-access
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-policy-no-statements-with-full-access",
		"This rule checks IAM policy no statements with full access.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.IAMPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range policies {
				id := ""
				if p.PolicyName != nil {
					id = *p.PolicyName
				} else if p.Arn != nil {
					id = *p.Arn
				}
				out, err := d.Clients.IAM.GetPolicyVersion(d.Ctx, &iam.GetPolicyVersionInput{
					PolicyArn: p.Arn,
					VersionId: p.DefaultVersionId,
				})
				if err != nil || out.PolicyVersion == nil || out.PolicyVersion.Document == nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Could not retrieve policy document"})
					continue
				}
				doc, err := decodePolicyDocument(*out.PolicyVersion.Document)
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Could not decode policy document"})
					continue
				}
				if hasFullAccess(doc) {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Policy has statements granting full access"})
				} else {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Policy has no full access statements"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-role-managed-policy-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-role-managed-policy-check",
		"This rule checks configuration for IAM role managed policy.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			roles, err := d.IAMRoles.Get()
			if err != nil {
				return nil, err
			}
			requiredPolicyARNs := iamParseCSV(os.Getenv("BPTOOLS_REQUIRED_ROLE_MANAGED_POLICY_ARNS"))
			if len(requiredPolicyARNs) == 0 {
				return []ConfigResource{{ID: "account", Passing: true, Detail: "No required role managed policies configured; default not-applicable behavior"}}, nil
			}
			var res []ConfigResource
			for _, r := range roles {
				roleName := ""
				if r.RoleName != nil {
					roleName = *r.RoleName
				}
				attached, err := iamListAllAttachedRolePolicyARNs(d, r.RoleName)
				if err != nil {
					res = append(res, ConfigResource{ID: roleName, Passing: false, Detail: "Error listing attached policies"})
					continue
				}
				missing := []string{}
				for _, required := range requiredPolicyARNs {
					if !attached[required] {
						missing = append(missing, required)
					}
				}
				res = append(res, ConfigResource{ID: roleName, Passing: len(missing) == 0, Detail: fmt.Sprintf("Missing required policies: %v", missing)})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-root-access-key-check
	// ---------------------------------------------------------------
	checker.Register(SingleCheck(
		"iam-root-access-key-check",
		"This rule checks configuration for IAM root access key.",
		"IAM", d,
		func(d *awsdata.Data) (bool, string, error) {
			summary, err := d.IAMAccountSummary.Get()
			if err != nil {
				return false, "", err
			}
			if count, ok := summary["AccountAccessKeysPresent"]; ok && count > 0 {
				return false, "Root account has access keys", nil
			}
			return true, "Root account has no access keys", nil
		},
	))

	// ---------------------------------------------------------------
	// iam-saml-provider-tagged
	// ---------------------------------------------------------------
	checker.Register(TaggedCheck(
		"iam-saml-provider-tagged",
		"This rule checks tagging for IAM SAML provider exist.",
		"IAM", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			providers, err := d.IAMSAMLProviders.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range providers {
				arn := ""
				if p.Arn != nil {
					arn = *p.Arn
				}
				out, err := d.Clients.IAM.GetSAMLProvider(d.Ctx, &iam.GetSAMLProviderInput{
					SAMLProviderArn: p.Arn,
				})
				if err != nil {
					res = append(res, TaggedResource{ID: arn, Tags: nil})
					continue
				}
				tags := make(map[string]string)
				for _, t := range out.Tags {
					if t.Key != nil && t.Value != nil {
						tags[*t.Key] = *t.Value
					}
				}
				res = append(res, TaggedResource{ID: arn, Tags: tags})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-server-certificate-expiration-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-server-certificate-expiration-check",
		"This rule checks expiration for IAM server certificate.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			certs, err := d.IAMServerCertificates.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range certs {
				id := ""
				if c.ServerCertificateName != nil {
					id = *c.ServerCertificateName
				}
				if c.Expiration != nil && c.Expiration.Before(time.Now()) {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Server certificate is expired"})
				} else {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Server certificate is not expired"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-server-certificate-tagged
	// ---------------------------------------------------------------
	checker.Register(TaggedCheck(
		"iam-server-certificate-tagged",
		"This rule checks tagging for IAM server certificate exist.",
		"IAM", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			certs, err := d.IAMServerCertificates.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, c := range certs {
				id := ""
				if c.ServerCertificateName != nil {
					id = *c.ServerCertificateName
				}
				out, err := d.Clients.IAM.GetServerCertificate(d.Ctx, &iam.GetServerCertificateInput{
					ServerCertificateName: c.ServerCertificateName,
				})
				if err != nil {
					res = append(res, TaggedResource{ID: id, Tags: nil})
					continue
				}
				tags := make(map[string]string)
				if out.ServerCertificate != nil {
					for _, t := range out.ServerCertificate.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-user-group-membership-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-user-group-membership-check",
		"This rule checks configuration for IAM user group membership.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			users, err := d.IAMUsers.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, u := range users {
				userName := ""
				if u.UserName != nil {
					userName = *u.UserName
				}
				out, err := d.Clients.IAM.ListGroupsForUser(d.Ctx, &iam.ListGroupsForUserInput{UserName: u.UserName})
				if err != nil {
					res = append(res, ConfigResource{ID: userName, Passing: false, Detail: "Error checking group membership"})
					continue
				}
				if len(out.Groups) > 0 {
					res = append(res, ConfigResource{ID: userName, Passing: true, Detail: "User belongs to at least one group"})
				} else {
					res = append(res, ConfigResource{ID: userName, Passing: false, Detail: "User does not belong to any group"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-user-mfa-enabled
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-user-mfa-enabled",
		"This rule checks enabled state for IAM user MFA.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			report, err := d.IAMCredentialReport.Get()
			if err != nil {
				return nil, err
			}
			rows, err := parseCredentialReport(report)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, row := range rows {
				if row.User == "<root_account>" {
					continue
				}
				if row.MFAActive == "true" {
					res = append(res, ConfigResource{ID: row.User, Passing: true, Detail: "MFA is enabled"})
				} else {
					res = append(res, ConfigResource{ID: row.User, Passing: false, Detail: "MFA is not enabled"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-user-no-policies-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-user-no-policies-check",
		"This rule checks configuration for IAM user no policies.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			users, err := d.IAMUsers.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, u := range users {
				userName := ""
				if u.UserName != nil {
					userName = *u.UserName
				}
				hasInline, err := iamUserHasInlinePolicies(d, u.UserName)
				if err != nil {
					res = append(res, ConfigResource{ID: userName, Passing: false, Detail: "Error listing inline policies"})
					continue
				}
				attached, err := iamListAllAttachedUserPolicyARNs(d, u.UserName)
				if err != nil {
					res = append(res, ConfigResource{ID: userName, Passing: false, Detail: "Error listing attached policies"})
					continue
				}
				hasAttached := len(attached) > 0

				if hasInline || hasAttached {
					res = append(res, ConfigResource{ID: userName, Passing: false, Detail: "User has directly attached policies"})
				} else {
					res = append(res, ConfigResource{ID: userName, Passing: true, Detail: "User has no directly attached policies"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// iam-user-unused-credentials-check
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"iam-user-unused-credentials-check",
		"This rule checks configuration for IAM user unused credentials.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			report, err := d.IAMCredentialReport.Get()
			if err != nil {
				return nil, err
			}
			rows, err := parseCredentialReport(report)
			if err != nil {
				return nil, err
			}
			maxDays := 90
			var res []ConfigResource
			for _, row := range rows {
				if row.User == "<root_account>" {
					continue
				}
				unused := false
				detail := "Credentials are in use"

				if row.PasswordEnabled == "true" && isCredentialUnused(row.PasswordLastUsed, maxDays) {
					unused = true
					detail = "Password unused for more than 90 days"
				}
				if row.AccessKey1Active == "true" && isCredentialUnused(row.AccessKey1LastUsed, maxDays) {
					unused = true
					detail = "Access key 1 unused for more than 90 days"
				}
				if row.AccessKey2Active == "true" && isCredentialUnused(row.AccessKey2LastUsed, maxDays) {
					unused = true
					detail = "Access key 2 unused for more than 90 days"
				}
				if unused {
					res = append(res, ConfigResource{ID: row.User, Passing: false, Detail: detail})
				} else {
					res = append(res, ConfigResource{ID: row.User, Passing: true, Detail: detail})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// mfa-enabled-for-iam-console-access
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"mfa-enabled-for-iam-console-access",
		"This rule checks MFA enabled for IAM console access.",
		"IAM", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			report, err := d.IAMCredentialReport.Get()
			if err != nil {
				return nil, err
			}
			rows, err := parseCredentialReport(report)
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, row := range rows {
				if row.PasswordEnabled != "true" {
					continue
				}
				if row.MFAActive == "true" {
					res = append(res, ConfigResource{ID: row.User, Passing: true, Detail: "MFA is enabled for console access"})
				} else {
					res = append(res, ConfigResource{ID: row.User, Passing: false, Detail: "MFA is not enabled for console access"})
				}
			}
			return res, nil
		},
	))

	// ---------------------------------------------------------------
	// root-account-hardware-mfa-enabled
	// ---------------------------------------------------------------
	checker.Register(SingleCheck(
		"root-account-hardware-mfa-enabled",
		"This rule checks enabled state for root account hardware MFA.",
		"IAM", d,
		func(d *awsdata.Data) (bool, string, error) {
			summary, err := d.IAMAccountSummary.Get()
			if err != nil {
				return false, "", err
			}
			mfaActive, _ := summary["AccountMFAEnabled"]
			if mfaActive == 0 {
				return false, "Root account MFA is not enabled", nil
			}
			// Check that MFA is hardware (not virtual)
			devices, err := d.IAMVirtualMFADevices.Get()
			if err != nil {
				return false, "", err
			}
			for _, dev := range devices {
				if dev.SerialNumber != nil && strings.Contains(*dev.SerialNumber, "root-account-mfa-device") {
					return false, "Root account uses virtual MFA, not hardware MFA", nil
				}
			}
			return true, "Root account has hardware MFA enabled", nil
		},
	))

	// ---------------------------------------------------------------
	// root-account-mfa-enabled
	// ---------------------------------------------------------------
	checker.Register(SingleCheck(
		"root-account-mfa-enabled",
		"This rule checks enabled state for root account MFA.",
		"IAM", d,
		func(d *awsdata.Data) (bool, string, error) {
			summary, err := d.IAMAccountSummary.Get()
			if err != nil {
				return false, "", err
			}
			mfaActive, _ := summary["AccountMFAEnabled"]
			if mfaActive > 0 {
				return true, "Root account MFA is enabled", nil
			}
			return false, "Root account MFA is not enabled", nil
		},
	))

	// ---------------------------------------------------------------
	// restricted-ssh
	// ---------------------------------------------------------------
	checker.Register(ConfigCheck(
		"restricted-ssh",
		"This rule checks restricted SSH.",
		"EC2", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, sg := range sgs {
				id := ""
				if sg.GroupId != nil {
					id = *sg.GroupId
				}
				open := isSSHOpenToWorld(sg)
				if open {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "SSH (port 22) is open to 0.0.0.0/0 or ::/0"})
				} else {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "SSH is properly restricted"})
				}
			}
			return res, nil
		},
	))

	// Suppress unused import warnings
	_ = io.Discard
	_ = iamtypes.PolicyScopeTypeLocal
	_ = ec2types.InstanceTypeA1Large
}

// isSSHOpenToWorld checks if a security group allows SSH (port 22) from 0.0.0.0/0 or ::/0.
func isSSHOpenToWorld(sg ec2types.SecurityGroup) bool {
	for _, perm := range sg.IpPermissions {
		// Check if this rule covers port 22
		coversPort22 := false
		if perm.IpProtocol != nil && *perm.IpProtocol == "-1" {
			coversPort22 = true
		} else if perm.FromPort != nil && perm.ToPort != nil && *perm.FromPort <= 22 && *perm.ToPort >= 22 {
			if perm.IpProtocol == nil || *perm.IpProtocol == "tcp" || *perm.IpProtocol == "-1" {
				coversPort22 = true
			}
		}
		if !coversPort22 {
			continue
		}
		for _, ipRange := range perm.IpRanges {
			if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
				return true
			}
		}
		for _, ipv6Range := range perm.Ipv6Ranges {
			if ipv6Range.CidrIpv6 != nil && *ipv6Range.CidrIpv6 == "::/0" {
				return true
			}
		}
	}
	return false
}
