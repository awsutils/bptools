package checks

import (
	"encoding/json"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
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
			var res []EnabledResource
			for id, enabled := range rot {
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
			var res []ConfigResource
			for id, p := range pols {
				ok := !policyAllowsStar(p)
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
			var res []TaggedResource
			for id, m := range tags {
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
				ok := !strings.Contains(a["Policy"], "\"Principal\":\"*\"")
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
				ok := !strings.Contains(a["Policy"], "\"Principal\":\"*\"")
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
				ok := !strings.Contains(a["Policy"], "\"Action\":\"*\"")
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
						logging = det.LoggingConfiguration != nil && len(det.LoggingConfiguration.Destinations) > 0
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
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
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
			for _, g := range igws {
				id := "unknown"
				if g.InternetGatewayId != nil {
					id = *g.InternetGatewayId
				}
				ok := len(g.Attachments) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Attached to VPC"})
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
					if e.RuleAction != "allow" || e.CidrBlock == nil || *e.CidrBlock != "0.0.0.0/0" {
						continue
					}
					if e.PortRange != nil {
						if (e.PortRange.From != nil && *e.PortRange.From == 22) || (e.PortRange.From != nil && *e.PortRange.From == 3389) {
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
					if r.DestinationCidrBlock != nil && *r.DestinationCidrBlock == "0.0.0.0/0" && r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "igw-") {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No 0.0.0.0/0 to IGW"})
			}
			return res, nil
		},
	))
}

func policyAllowsStar(policy string) bool {
	var obj map[string]any
	if err := json.Unmarshal([]byte(policy), &obj); err != nil {
		return false
	}
	stmts, ok := obj["Statement"].([]any)
	if !ok {
		return false
	}
	for _, s := range stmts {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if eff, _ := m["Effect"].(string); strings.EqualFold(eff, "Allow") {
			if p, ok := m["Principal"].(map[string]any); ok {
				if aws, ok := p["AWS"]; ok {
					if aws == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}
