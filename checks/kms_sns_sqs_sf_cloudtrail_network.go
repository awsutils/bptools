package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

// RegisterMiscSecurityChecks registers KMS/SNS/SQS/StepFunctions/CloudTrail/network checks.
func RegisterMiscSecurityChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"cmk-backing-key-rotation-enabled",
		"This rule checks cmk backing key rotation enabled.",
		"kms",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			rot, err := d.KMSKeyRotationStatus.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.KMSKeyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, enabled := range rot {
				if shouldSkipAWSManagedKMSKey(id, details) {
					continue
				}
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"kms-cmk-not-scheduled-for-deletion",
		"This rule checks kms cmk not scheduled for deletion.",
		"kms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			details, err := d.KMSKeyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, meta := range details {
				ok := meta.KeyState != "PendingDeletion" && meta.KeyState != "PendingReplicaDeletion"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "KeyState not pending deletion"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"kms-key-policy-no-public-access",
		"This rule checks kms key policy no public access.",
		"kms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			pols, err := d.KMSKeyPolicies.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.KMSKeyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, p := range pols {
				if shouldSkipAWSManagedKMSKey(id, details) {
					continue
				}
				ok := !policyHasPublicAllow(p)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No wildcard principal"})
			}
			return res, nil
		},
	))
	checker.Register(TaggedCheck(
		"kms-key-tagged",
		"This rule checks kms key tagged.",
		"kms",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			tags, err := d.KMSKeyTags.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.KMSKeyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for id, m := range tags {
				if shouldSkipAWSManagedKMSKey(id, details) {
					continue
				}
				res = append(res, TaggedResource{ID: id, Tags: m})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"sns-encrypted-kms",
		"This rule checks sns encrypted kms.",
		"sns",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			attrs, err := d.SNSTopicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, a := range attrs {
				enabled := a["KmsMasterKeyId"] != ""
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(EnabledCheck(
		"sns-topic-message-delivery-notification-enabled",
		"This rule checks sns topic message delivery notification enabled.",
		"sns",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			attrs, err := d.SNSTopicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, a := range attrs {
				enabled := a["DeliveryStatusSuccessSamplingRate"] != "" || a["DeliveryStatusFailureSamplingRate"] != ""
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"sns-topic-no-public-access",
		"This rule checks sns topic no public access.",
		"sns",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			attrs, err := d.SNSTopicAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, a := range attrs {
				ok := !policyHasPublicAllow(a["Policy"])
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Policy not public"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sqs-queue-dlq-check",
		"This rule checks sqs queue dlq check.",
		"sqs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			attrs, err := d.SQSQueueAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for url, a := range attrs {
				ok := a["RedrivePolicy"] != ""
				res = append(res, ConfigResource{ID: url, Passing: ok, Detail: "RedrivePolicy set"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"sqs-queue-no-public-access",
		"This rule checks sqs queue no public access.",
		"sqs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			attrs, err := d.SQSQueueAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for url, a := range attrs {
				ok := !policyHasPublicAllow(a["Policy"])
				res = append(res, ConfigResource{ID: url, Passing: ok, Detail: "Policy not public"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"sqs-queue-policy-full-access-check",
		"This rule checks sqs queue policy full access check.",
		"sqs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			attrs, err := d.SQSQueueAttributes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for url, a := range attrs {
				ok := !policyAllowsPublicSQSFullAccess(a["Policy"])
				res = append(res, ConfigResource{ID: url, Passing: ok, Detail: "No full access policy"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"stepfunctions-state-machine-tagged",
		"This rule checks stepfunctions state machine tagged.",
		"stepfunctions",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			machines, err := d.SFNStateMachines.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SFNStateMachineTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range machines {
				id := "unknown"
				if m.StateMachineArn != nil {
					id = *m.StateMachineArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"step-functions-state-machine-logging-enabled",
		"This rule checks step functions state machine logging enabled.",
		"stepfunctions",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			machines, err := d.SFNStateMachines.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.SFNStateMachineDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, m := range machines {
				id := "unknown"
				if m.StateMachineArn != nil {
					id = *m.StateMachineArn
				}
				logging := false
				if m.StateMachineArn != nil {
					if det, ok := details[*m.StateMachineArn]; ok {
						logging = det.LoggingConfiguration != nil &&
							len(det.LoggingConfiguration.Destinations) > 0 &&
							det.LoggingConfiguration.Level != sfntypes.LogLevelOff
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"multi-region-cloudtrail-enabled",
		"This rule checks multi region cloudtrail enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			accountCompliant := false
			for id, t := range trails {
				if t.IsMultiRegionTrail == nil || !*t.IsMultiRegionTrail {
					continue
				}
				trailIsLogging := false
				for _, key := range []string{id, stringValue(t.TrailARN), stringValue(t.Name)} {
					if key == "" {
						continue
					}
					if st, ok := statuses[key]; ok && st.IsLogging != nil && *st.IsLogging {
						trailIsLogging = true
						break
					}
				}
				if !trailIsLogging {
					continue
				}
				for _, key := range []string{id, stringValue(t.TrailARN), stringValue(t.Name)} {
					if key == "" {
						continue
					}
					if selectorSet, ok := events[key]; ok && managementSelectorsCoverAll(selectorSet.EventSelectors, selectorSet.AdvancedEventSelectors) {
						accountCompliant = true
						break
					}
				}
				if accountCompliant {
					break
				}
			}
			if len(trails) == 0 {
				return []EnabledResource{{ID: "account", Enabled: false}}, nil
			}
			return []EnabledResource{{ID: "account", Enabled: accountCompliant}}, nil
		},
	))

	checker.Register(ConfigCheck(
		"db-instance-backup-enabled",
		"This rule checks db instance backup enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				ok := inst.BackupRetentionPeriod != nil && *inst.BackupRetentionPeriod > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Backup retention > 0"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"internet-gateway-authorized-vpc-only",
		"This rule checks internet gateway authorized vpc only.",
		"ec2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			igws, err := d.EC2InternetGateways.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			allowedVPCs := allowedVPCSetFromEnv("BPTOOLS_AUTHORIZED_IGW_VPC_IDS")
			for _, g := range igws {
				id := "unknown"
				if g.InternetGatewayId != nil {
					id = *g.InternetGatewayId
				}
				ok := true
				for _, a := range g.Attachments {
					if a.VpcId == nil || strings.TrimSpace(*a.VpcId) == "" {
						ok = false
						break
					}
					if len(allowedVPCs) > 0 && !allowedVPCs[*a.VpcId] {
						ok = false
						break
					}
				}
				detail := fmt.Sprintf("Attachment count: %d", len(g.Attachments))
				if len(allowedVPCs) > 0 {
					detail = fmt.Sprintf("Attachment count: %d, authorized VPC policy enforced", len(g.Attachments))
				} else {
					detail = "No authorized VPC list configured; default allow-all behavior"
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"nacl-no-unrestricted-ssh-rdp",
		"This rule checks nacl no unrestricted ssh rdp.",
		"ec2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			acls, err := d.EC2NetworkACLs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, acl := range acls {
				id := "unknown"
				if acl.NetworkAclId != nil {
					id = *acl.NetworkAclId
				}
				ok := true
				for _, e := range acl.Entries {
					if e.Egress != nil && *e.Egress {
						continue
					}
					public := (e.CidrBlock != nil && *e.CidrBlock == "0.0.0.0/0") || (e.Ipv6CidrBlock != nil && *e.Ipv6CidrBlock == "::/0")
					if e.RuleAction != "allow" || !public {
						continue
					}
					if e.PortRange != nil {
						if portRangeIncludes(e.PortRange.From, e.PortRange.To, 22) || portRangeIncludes(e.PortRange.From, e.PortRange.To, 3389) {
							ok = false
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No 0.0.0.0/0 SSH/RDP"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"no-unrestricted-route-to-igw",
		"This rule checks no unrestricted route to igw.",
		"ec2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rts, err := d.EC2RouteTables.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, rt := range rts {
				id := "unknown"
				if rt.RouteTableId != nil {
					id = *rt.RouteTableId
				}
				ok := true
				for _, r := range rt.Routes {
					defaultRoute := (r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == "0.0.0.0/0") ||
						(r.DestinationIpv6CidrBlock != nil && *r.DestinationIpv6CidrBlock == "::/0")
					if defaultRoute && r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "igw-") {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No default route to IGW"})
			}
			return res, nil
		},
	))
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func portRangeIncludes(from *int32, to *int32, port int32) bool {
	if from == nil || to == nil {
		return true
	}
	return port >= *from && port <= *to
}

func managementSelectorsCoverAll(selectors []cloudtrailtypes.EventSelector, advanced []cloudtrailtypes.AdvancedEventSelector) bool {
	for _, selector := range selectors {
		includeMgmt := selector.IncludeManagementEvents == nil || *selector.IncludeManagementEvents
		if !includeMgmt {
			continue
		}
		if len(selector.ExcludeManagementEventSources) > 0 {
			continue
		}
		if selector.ReadWriteType == "" || selector.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll {
			return true
		}
	}
	for _, selector := range advanced {
		hasCategory := false
		hasReadOnly := false
		readOnlyTrue := false
		readOnlyFalse := false
		scoped := false
		for _, field := range selector.FieldSelectors {
			if field.Field == nil {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(*field.Field))
			switch name {
			case "eventcategory":
				hasCategory = containsCI(field.Equals, "management")
			case "readonly":
				hasReadOnly = true
				readOnlyTrue = containsCI(field.Equals, "true")
				readOnlyFalse = containsCI(field.Equals, "false")
			default:
				if len(field.Equals) > 0 || len(field.NotEquals) > 0 || len(field.StartsWith) > 0 || len(field.NotStartsWith) > 0 || len(field.EndsWith) > 0 || len(field.NotEndsWith) > 0 {
					scoped = true
				}
			}
		}
		if hasCategory && !scoped && (!hasReadOnly || (readOnlyTrue && readOnlyFalse)) {
			return true
		}
	}
	return false
}

func containsCI(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

type simplePolicyDocument struct {
	Statement any `json:"Statement"`
}

type simpleStatement struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"`
	Action    interface{} `json:"Action"`
}

func decodePolicyStatements(policy string) []simpleStatement {
	if strings.TrimSpace(policy) == "" {
		return nil
	}
	var doc simplePolicyDocument
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return nil
	}
	switch s := doc.Statement.(type) {
	case []interface{}:
		out := make([]simpleStatement, 0, len(s))
		for _, item := range s {
			raw, err := json.Marshal(item)
			if err != nil {
				continue
			}
			var stmt simpleStatement
			if err := json.Unmarshal(raw, &stmt); err != nil {
				continue
			}
			out = append(out, stmt)
		}
		return out
	case map[string]interface{}:
		raw, err := json.Marshal(s)
		if err != nil {
			return nil
		}
		var stmt simpleStatement
		if err := json.Unmarshal(raw, &stmt); err != nil {
			return nil
		}
		return []simpleStatement{stmt}
	}
	return nil
}

func principalIsPublic(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return strings.TrimSpace(p) == "*"
	case map[string]interface{}:
		for _, value := range p {
			switch typed := value.(type) {
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

func actionStrings(action interface{}) []string {
	switch a := action.(type) {
	case string:
		return []string{a}
	case []interface{}:
		out := make([]string, 0, len(a))
		for _, value := range a {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func policyHasPublicAllow(policy string) bool {
	for _, stmt := range decodePolicyStatements(policy) {
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "Allow") {
			continue
		}
		if principalIsPublic(stmt.Principal) {
			return true
		}
	}
	return false
}

func policyAllowsPublicSQSFullAccess(policy string) bool {
	for _, stmt := range decodePolicyStatements(policy) {
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "Allow") {
			continue
		}
		if !principalIsPublic(stmt.Principal) {
			continue
		}
		for _, action := range actionStrings(stmt.Action) {
			a := strings.ToLower(strings.TrimSpace(action))
			if a == "*" || a == "sqs:*" {
				return true
			}
		}
	}
	return false
}

func allowedVPCSetFromEnv(name string) map[string]bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil
	}
	out := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		item := strings.TrimSpace(part)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func boolEnvDefaultTrueLocal(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "", "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return true
	}
}

func shouldSkipAWSManagedKMSKey(keyID string, details map[string]kmstypes.KeyMetadata) bool {
	if !boolEnvDefaultTrueLocal("BPTOOLS_IGNORE_AWS_MANAGED_KMS_KEYS") {
		return false
	}
	meta, ok := details[keyID]
	if !ok {
		return false
	}
	return strings.EqualFold(string(meta.KeyManager), "AWS")
}
