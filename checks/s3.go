package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

func bucketName(b s3types.Bucket) string {
	if b.Name != nil {
		return *b.Name
	}
	return "unknown"
}

func RegisterS3Checks(d *awsdata.Data) {
	// s3-bucket-tagged
	checker.Register(TaggedCheck("s3-bucket-tagged", "Checks if Amazon S3 buckets have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.", "s3", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, b := range buckets {
				tags := make(map[string]string)
				out, err := d.Clients.S3.GetBucketTagging(d.Ctx, &s3.GetBucketTaggingInput{Bucket: b.Name})
				if err == nil {
					for _, t := range out.TagSet {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
				}
				res = append(res, TaggedResource{ID: bucketName(b), Tags: tags})
			}
			return res, nil
		}))

	// s3-bucket-versioning-enabled
	checker.Register(EnabledCheck("s3-bucket-versioning-enabled", "Checks if versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets.", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketVersioning(d.Ctx, &s3.GetBucketVersioningInput{Bucket: b.Name})
				enabled := err == nil && out.Status == s3types.BucketVersioningStatusEnabled
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
			}
			return res, nil
		}))

	// s3-bucket-server-side-encryption-enabled
	checker.Register(EnabledCheck("s3-bucket-server-side-encryption-enabled", "Checks if your Amazon S3 bucket either has the Amazon S3 default encryption enabled or that the Amazon S3 bucket policy explicitly denies put-object requests without server side encryption that uses AES-256 or AWS Key Management Service. The rule is NON_COMPLIANT if your Amazon S3 bucket is not encrypted by default.", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				_, err := d.Clients.S3.GetBucketEncryption(d.Ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: err == nil})
			}
			return res, nil
		}))

	// s3-bucket-logging-enabled
	checker.Register(LoggingCheck("s3-bucket-logging-enabled", "Checks if logging is enabled for your S3 buckets. The rule is NON_COMPLIANT if logging is not enabled.", "s3", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketLogging(d.Ctx, &s3.GetBucketLoggingInput{Bucket: b.Name})
				logging := err == nil && out.LoggingEnabled != nil
				res = append(res, LoggingResource{ID: bucketName(b), Logging: logging})
			}
			return res, nil
		}))

	// s3-bucket-public-read-prohibited + s3-bucket-public-write-prohibited + s3-bucket-level-public-access-prohibited
	checker.Register(ConfigCheck("s3-bucket-public-read-prohibited", "Checks if your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicyStatus(d.Ctx, &s3.GetBucketPolicyStatusInput{Bucket: b.Name})
				public := err == nil && out.PolicyStatus != nil && out.PolicyStatus.IsPublic != nil && *out.PolicyStatus.IsPublic
				res = append(res, ConfigResource{ID: bucketName(b), Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-public-write-prohibited", "Checks if your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				fullyBlocked := false
				blockOut, err := d.Clients.S3.GetPublicAccessBlock(d.Ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
				if err == nil && blockOut.PublicAccessBlockConfiguration != nil {
					cfg := blockOut.PublicAccessBlockConfiguration
					fullyBlocked = cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
						cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
						cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
						cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
				}
				if fullyBlocked {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: true, Detail: "All public access block settings enabled"})
					continue
				}
				aclOut, aclErr := d.Clients.S3.GetBucketAcl(d.Ctx, &s3.GetBucketAclInput{Bucket: b.Name})
				publicWriteACL := aclErr == nil && s3ACLAllowsPublicWrite(aclOut)
				publicWritePolicy := false
				polOut, polErr := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				if polErr == nil && polOut.Policy != nil {
					publicWritePolicy = s3PolicyAllowsPublicWrite(*polOut.Policy)
				}
				publicWrite := publicWriteACL || publicWritePolicy
				res = append(res, ConfigResource{ID: bucketName(b), Passing: !publicWrite, Detail: fmt.Sprintf("Public write via ACL/policy: %v", publicWrite)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-level-public-access-prohibited", "Checks if S3 buckets are publicly accessible. The rule is NON_COMPLIANT if an S3 bucket is not listed in the excludedPublicBuckets parameter and bucket level settings are public.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetPublicAccessBlock(d.Ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
				blocked := err == nil && out.PublicAccessBlockConfiguration != nil &&
					out.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *out.PublicAccessBlockConfiguration.BlockPublicAcls &&
					out.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *out.PublicAccessBlockConfiguration.IgnorePublicAcls &&
					out.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *out.PublicAccessBlockConfiguration.BlockPublicPolicy &&
					out.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *out.PublicAccessBlockConfiguration.RestrictPublicBuckets
				res = append(res, ConfigResource{ID: bucketName(b), Passing: blocked, Detail: fmt.Sprintf("All public access blocked: %v", blocked)})
			}
			return res, nil
		}))

	// s3-bucket-ssl-requests-only
	checker.Register(ConfigCheck("s3-bucket-ssl-requests-only", "Checks if S3 buckets have policies that require requests to use SSL/TLS. The rule is NON_COMPLIANT if any S3 bucket has policies allowing HTTP requests.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				if err != nil || out.Policy == nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: false, Detail: "No bucket policy"})
					continue
				}
				hasSSL := s3PolicyDeniesInsecureTransport(*out.Policy)
				res = append(res, ConfigResource{ID: bucketName(b), Passing: hasSSL, Detail: fmt.Sprintf("Deny insecure transport statement found: %v", hasSSL)})
			}
			return res, nil
		}))

	// s3-bucket-cross-region-replication-enabled + s3-bucket-replication-enabled
	for _, id := range []string{"s3-bucket-cross-region-replication-enabled", "s3-bucket-replication-enabled"} {
		cid := id
		checker.Register(EnabledCheck(cid, "Check replication", "s3", d,
			func(d *awsdata.Data) ([]EnabledResource, error) {
				buckets, err := d.S3Buckets.Get()
				if err != nil {
					return nil, err
				}
				var res []EnabledResource
				for _, b := range buckets {
					out, err := d.Clients.S3.GetBucketReplication(d.Ctx, &s3.GetBucketReplicationInput{Bucket: b.Name})
					enabled := err == nil && out.ReplicationConfiguration != nil && len(out.ReplicationConfiguration.Rules) > 0
					if enabled && cid == "s3-bucket-cross-region-replication-enabled" {
						sourceRegion, srcErr := s3BucketRegion(d, b.Name)
						if srcErr != nil || sourceRegion == "" {
							enabled = false
						} else {
							crossRegion := false
							for _, rule := range out.ReplicationConfiguration.Rules {
								if rule.Status != s3types.ReplicationRuleStatusEnabled || rule.Destination == nil || rule.Destination.Bucket == nil {
									continue
								}
								destBucket := s3DestinationBucketName(*rule.Destination.Bucket)
								if destBucket == "" {
									continue
								}
								destRegion, destErr := s3BucketRegion(d, &destBucket)
								if destErr != nil || destRegion == "" {
									continue
								}
								if !strings.EqualFold(sourceRegion, destRegion) {
									crossRegion = true
									break
								}
							}
							enabled = crossRegion
						}
					}
					res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
				}
				return res, nil
			}))
		_ = cid
	}

	// s3-bucket-default-lock-enabled
	checker.Register(EnabledCheck("s3-bucket-default-lock-enabled", "Checks if the S3 bucket has lock enabled, by default. The rule is NON_COMPLIANT if the lock is not enabled.", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				_, err := d.Clients.S3.GetObjectLockConfiguration(d.Ctx, &s3.GetObjectLockConfigurationInput{Bucket: b.Name})
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: err == nil})
			}
			return res, nil
		}))

	// s3-bucket-mfa-delete-enabled
	checker.Register(EnabledCheck("s3-bucket-mfa-delete-enabled", "Checks if MFA Delete is enabled in the Amazon Simple Storage Service (Amazon S3) bucket versioning configuration. The rule is NON_COMPLIANT if MFA Delete is not enabled.", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketVersioning(d.Ctx, &s3.GetBucketVersioningInput{Bucket: b.Name})
				enabled := err == nil && out.MFADelete == s3types.MFADeleteStatusEnabled
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
			}
			return res, nil
		}))

	// s3-bucket-acl-prohibited
	checker.Register(ConfigCheck("s3-bucket-acl-prohibited", "Checks if Amazon Simple Storage Service (Amazon S3) Buckets allow user permissions through access control lists (ACLs). The rule is NON_COMPLIANT if ACLs are configured for user access in Amazon S3 Buckets.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketAcl(d.Ctx, &s3.GetBucketAclInput{Bucket: b.Name})
				if err != nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: false, Detail: "Unable to read bucket ACL"})
					continue
				}
				aclProhibited := s3OnlyOwnerHasACL(out)
				res = append(res, ConfigResource{ID: bucketName(b), Passing: aclProhibited, Detail: fmt.Sprintf("Only owner ACL grants: %v", aclProhibited)})
			}
			return res, nil
		}))

	// s3-default-encryption-kms
	checker.Register(ConfigCheck("s3-default-encryption-kms", "Checks if the S3 buckets are encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the S3 bucket is not encrypted with an AWS KMS key.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketEncryption(d.Ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
				kms := false
				if err == nil && out.ServerSideEncryptionConfiguration != nil {
					for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
						if rule.ApplyServerSideEncryptionByDefault != nil && rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm == s3types.ServerSideEncryptionAwsKms {
							kms = true
						}
					}
				}
				res = append(res, ConfigResource{ID: bucketName(b), Passing: kms, Detail: fmt.Sprintf("KMS encryption: %v", kms)})
			}
			return res, nil
		}))

	// s3-event-notifications-enabled
	checker.Register(EnabledCheck("s3-event-notifications-enabled", "Checks if Amazon S3 Events Notifications are enabled on an S3 bucket. The rule is NON_COMPLIANT if S3 Events Notifications are not set on a bucket, or if the event type or destination do not match the eventTypes and destinationArn parameters.", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketNotificationConfiguration(d.Ctx, &s3.GetBucketNotificationConfigurationInput{Bucket: b.Name})
				has := err == nil && (len(out.LambdaFunctionConfigurations) > 0 || len(out.QueueConfigurations) > 0 || len(out.TopicConfigurations) > 0)
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: has})
			}
			return res, nil
		}))

	// s3-lifecycle-policy-check + s3-version-lifecycle-policy-check
	for _, id := range []string{"s3-lifecycle-policy-check", "s3-version-lifecycle-policy-check"} {
		cid := id
		checker.Register(ConfigCheck(cid, "Check lifecycle policy", "s3", d,
			func(d *awsdata.Data) ([]ConfigResource, error) {
				buckets, err := d.S3Buckets.Get()
				if err != nil {
					return nil, err
				}
				var res []ConfigResource
				for _, b := range buckets {
					_, err := d.Clients.S3.GetBucketLifecycleConfiguration(d.Ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: b.Name})
					res = append(res, ConfigResource{ID: bucketName(b), Passing: err == nil, Detail: fmt.Sprintf("Lifecycle policy: %v", err == nil)})
				}
				return res, nil
			}))
		_ = cid
	}

	// s3-account-level-public-access-blocks + s3-account-level-public-access-blocks-periodic
	for _, id := range []string{"s3-account-level-public-access-blocks", "s3-account-level-public-access-blocks-periodic"} {
		cid := id
		checker.Register(SingleCheck(cid, "Check account public access block", "s3", d,
			func(d *awsdata.Data) (bool, string, error) {
				acctID, err := d.AccountID.Get()
				if err != nil {
					return false, "", err
				}
				out, err := d.Clients.S3Control.GetPublicAccessBlock(d.Ctx, &s3control.GetPublicAccessBlockInput{AccountId: &acctID})
				if err != nil {
					return false, "No account-level public access block", nil
				}
				cfg := out.PublicAccessBlockConfiguration
				blocked := cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
					cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
					cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
					cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
				return blocked, fmt.Sprintf("Account public access blocked: %v", blocked), nil
			}))
		_ = cid
	}

	checker.Register(ConfigCheck("s3-access-point-in-vpc-only", "Checks if an Amazon S3 access point does not allow access from the internet (NetworkOrigin is VPC). The rule is NON_COMPLIANT if NetworkOrigin is Internet.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			out, err := d.Clients.S3Control.ListAccessPoints(d.Ctx, &s3control.ListAccessPointsInput{AccountId: &accountID})
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ap := range out.AccessPointList {
				name := ""
				if ap.Name != nil {
					name = *ap.Name
				}
				inVPC := ap.NetworkOrigin == "VPC" || ap.VpcConfiguration != nil
				res = append(res, ConfigResource{ID: name, Passing: inVPC, Detail: fmt.Sprintf("NetworkOrigin: %s", ap.NetworkOrigin)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-access-point-public-access-blocks", "Checks if Amazon S3 access points have block public access settings enabled. The rule is NON_COMPLIANT if block public access settings are not enabled for S3 access points.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			accountID, err := d.AccountID.Get()
			if err != nil {
				return nil, err
			}
			out, err := d.Clients.S3Control.ListAccessPoints(d.Ctx, &s3control.ListAccessPointsInput{AccountId: &accountID})
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ap := range out.AccessPointList {
				if ap.Name == nil {
					continue
				}
				detail, err := d.Clients.S3Control.GetAccessPoint(d.Ctx, &s3control.GetAccessPointInput{AccountId: &accountID, Name: ap.Name})
				if err != nil {
					res = append(res, ConfigResource{ID: *ap.Name, Passing: false, Detail: "Unable to read access point configuration"})
					continue
				}
				cfg := detail.PublicAccessBlockConfiguration
				blocked := cfg != nil &&
					cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
					cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
					cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
					cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
				res = append(res, ConfigResource{ID: *ap.Name, Passing: blocked, Detail: fmt.Sprintf("All public access blocks enabled: %v", blocked)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-policy-not-more-permissive", "Checks if your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			controlPolicy := strings.TrimSpace(os.Getenv("BPTOOLS_S3_CONTROL_POLICY_JSON"))
			if controlPolicy == "" {
				return []ConfigResource{{ID: "account", Passing: true, Detail: "Missing control policy env var; default not-applicable behavior"}}, nil
			}
			if _, err := s3PolicyStatements(controlPolicy); err != nil {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "Invalid control policy document in BPTOOLS_S3_CONTROL_POLICY_JSON"}}, nil
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				if err != nil || out.Policy == nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: true, Detail: "No bucket policy"})
					continue
				}
				ok, detail := s3PolicyNotMorePermissive(*out.Policy, controlPolicy)
				res = append(res, ConfigResource{ID: bucketName(b), Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-policy-grantee-check", "Checks that the access granted by the Amazon S3 bucket is restricted by any of the AWS principals, federated users, service principals, IP addresses, or VPCs that you provide. The rule is COMPLIANT if a bucket policy is not present.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			type statement struct {
				Effect    string      `json:"Effect"`
				Principal interface{} `json:"Principal"`
			}
			type policyDoc struct {
				Statement []statement `json:"Statement"`
			}
			hasPublicPrincipal := func(principal interface{}) bool {
				switch p := principal.(type) {
				case string:
					return p == "*"
				case map[string]interface{}:
					for _, v := range p {
						if s, ok := v.(string); ok && s == "*" {
							return true
						}
					}
				}
				return false
			}
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				if err != nil || out.Policy == nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: true, Detail: "No bucket policy"})
					continue
				}
				var doc policyDoc
				if err := json.Unmarshal([]byte(*out.Policy), &doc); err != nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: false, Detail: "Invalid bucket policy document"})
					continue
				}
				public := false
				for _, st := range doc.Statement {
					if strings.EqualFold(st.Effect, "Allow") && hasPublicPrincipal(st.Principal) {
						public = true
						break
					}
				}
				res = append(res, ConfigResource{ID: bucketName(b), Passing: !public, Detail: fmt.Sprintf("Public policy grantee found: %v", public)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-blacklisted-actions-prohibited", "Checks if an Amazon Simple Storage Service (Amazon S3) bucket policy does not allow blocklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts. For example, the rule checks that the Amazon S3 bucket policy does not allow another AWS account to perform any s3:GetBucket* actions and s3:DeleteObject on any object in the bucket. The rule is NON_COMPLIANT if any blocklisted actions are allowed by the Amazon S3 bucket policy.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			type statement struct {
				Effect string      `json:"Effect"`
				Action interface{} `json:"Action"`
			}
			type policyDoc struct {
				Statement []statement `json:"Statement"`
			}
			toActions := func(action interface{}) []string {
				switch a := action.(type) {
				case string:
					return []string{a}
				case []interface{}:
					var out []string
					for _, v := range a {
						if s, ok := v.(string); ok {
							out = append(out, s)
						}
					}
					return out
				default:
					return nil
				}
			}
			blacklist := map[string]bool{"s3:putbucketacl": true, "s3:putbucketpolicy": true, "s3:putobjectacl": true}
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				if err != nil || out.Policy == nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: true, Detail: "No bucket policy"})
					continue
				}
				var doc policyDoc
				if err := json.Unmarshal([]byte(*out.Policy), &doc); err != nil {
					res = append(res, ConfigResource{ID: bucketName(b), Passing: false, Detail: "Invalid bucket policy document"})
					continue
				}
				found := ""
				for _, st := range doc.Statement {
					if !strings.EqualFold(st.Effect, "Allow") {
						continue
					}
					for _, a := range toActions(st.Action) {
						la := strings.ToLower(a)
						if blacklist[la] || la == "s3:*" || la == "*" {
							found = a
							break
						}
					}
					if found != "" {
						break
					}
				}
				res = append(res, ConfigResource{ID: bucketName(b), Passing: found == "", Detail: fmt.Sprintf("Blacklisted allowed action: %s", found)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3express-dir-bucket-lifecycle-rules-check", "Checks if lifecycle rules are configured for an Amazon S3 Express directory bucket. The rule is NON_COMPLIANT if there is no active lifecycle configuration rules or the configuration does not match with the parameter values.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				if b.Name == nil {
					continue
				}
				name := *b.Name
				if !strings.Contains(name, "--x-s3") {
					continue
				}
				out, err := d.Clients.S3.GetBucketLifecycleConfiguration(d.Ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: b.Name})
				ok := err == nil && len(out.Rules) > 0
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Lifecycle rules: %d", len(out.Rules))})
			}
			return res, nil
		}))

	loadBackupState := func() (map[string]bool, map[string]time.Time, map[string]bool, error) {
		protected, err := d.BackupProtectedResources.Get()
		if err != nil {
			return nil, nil, nil, err
		}
		vaults, err := d.BackupVaultLockConfigs.Get()
		if err != nil {
			return nil, nil, nil, err
		}
		isProtected := make(map[string]bool)
		lastBackup := make(map[string]time.Time)
		inProtectedVault := make(map[string]bool)
		for arn, resource := range protected {
			if !strings.HasPrefix(arn, "arn:aws:s3:::") {
				continue
			}
			isProtected[arn] = true
			if resource.LastBackupTime != nil {
				lastBackup[arn] = *resource.LastBackupTime
			}
			vaultProtected := false
			if resource.LastBackupVaultArn != nil {
				parts := strings.Split(*resource.LastBackupVaultArn, ":")
				if len(parts) > 0 {
					name := parts[len(parts)-1]
					name = strings.TrimPrefix(name, "backup-vault/")
					if vault, ok := vaults[name]; ok {
						if vault.Locked != nil && *vault.Locked {
							vaultProtected = true
						}
						if strings.Contains(strings.ToUpper(string(vault.VaultType)), "LOGICALLY_AIR_GAPPED") {
							vaultProtected = true
						}
					}
				}
			}
			inProtectedVault[arn] = vaultProtected
		}
		return isProtected, lastBackup, inProtectedVault, nil
	}

	checker.Register(ConfigCheck("s3-resources-protected-by-backup-plan", "Checks if Amazon Simple Storage Service (Amazon S3) buckets are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon S3 bucket is not covered by a backup plan.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			isProtected, _, _, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				id := bucketName(b)
				arn := "arn:aws:s3:::" + id
				res = append(res, ConfigResource{ID: id, Passing: isProtected[arn], Detail: fmt.Sprintf("Protected by backup plan: %v", isProtected[arn])})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-last-backup-recovery-point-created", "Checks if a recovery point was created for Amazon Simple Storage Service (Amazon S3). The rule is NON_COMPLIANT if the Amazon S3 bucket does not have a corresponding recovery point created within the specified time period.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				id := bucketName(b)
				arn := "arn:aws:s3:::" + id
				ok, detail := backupRecencyResult(rps[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-meets-restore-time-target", "Checks if the restore time of Amazon Simple Storage Service (Amazon S3) buckets meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon S3 bucket is greater than maxRestoreTime minutes.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				id := bucketName(b)
				arn := "arn:aws:s3:::" + id
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-resources-in-logically-air-gapped-vault", "Checks if Amazon Simple Storage Service (Amazon S3) buckets are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon S3 bucket is not in a logically air-gapped vault within the specified time period.", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil {
				return nil, err
			}
			_, _, inProtectedVault, err := loadBackupState()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buckets {
				id := bucketName(b)
				arn := "arn:aws:s3:::" + id
				res = append(res, ConfigResource{ID: id, Passing: inProtectedVault[arn], Detail: fmt.Sprintf("In locked/air-gapped vault: %v", inProtectedVault[arn])})
			}
			return res, nil
		}))
}

func s3DestinationBucketName(destination string) string {
	value := strings.TrimSpace(destination)
	if value == "" {
		return ""
	}
	const prefix = "arn:aws:s3:::"
	if strings.HasPrefix(strings.ToLower(value), prefix) {
		return strings.TrimPrefix(value, prefix)
	}
	return value
}

func s3BucketRegion(d *awsdata.Data, bucket *string) (string, error) {
	if bucket == nil || strings.TrimSpace(*bucket) == "" {
		return "", fmt.Errorf("missing bucket")
	}
	out, err := d.Clients.S3.GetBucketLocation(d.Ctx, &s3.GetBucketLocationInput{Bucket: bucket})
	if err != nil {
		return "", err
	}
	location := strings.TrimSpace(string(out.LocationConstraint))
	if location == "" {
		return "us-east-1", nil
	}
	if strings.EqualFold(location, "EU") {
		return "eu-west-1", nil
	}
	return strings.ToLower(location), nil
}

type s3PolicyStatement struct {
	Effect    string         `json:"Effect"`
	Action    interface{}    `json:"Action"`
	Resource  interface{}    `json:"Resource"`
	Principal interface{}    `json:"Principal"`
	Condition map[string]any `json:"Condition"`
}

func s3PolicyStatements(policy string) ([]s3PolicyStatement, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(policy), &raw); err != nil {
		return nil, err
	}
	statementRaw, ok := raw["Statement"]
	if !ok {
		return nil, nil
	}
	var single s3PolicyStatement
	if err := json.Unmarshal(statementRaw, &single); err == nil && (single.Effect != "" || single.Action != nil || single.Principal != nil || single.Condition != nil) {
		return []s3PolicyStatement{single}, nil
	}
	var many []s3PolicyStatement
	if err := json.Unmarshal(statementRaw, &many); err != nil {
		return nil, err
	}
	return many, nil
}

func s3PolicyDeniesInsecureTransport(policy string) bool {
	statements, err := s3PolicyStatements(policy)
	if err != nil {
		return false
	}
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Deny") || st.Condition == nil {
			continue
		}
		for conditionType, conditionValues := range st.Condition {
			if !strings.EqualFold(conditionType, "Bool") {
				continue
			}
			m, ok := conditionValues.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range m {
				if strings.EqualFold(key, "aws:SecureTransport") && strings.EqualFold(fmt.Sprint(value), "false") {
					return true
				}
			}
		}
	}
	return false
}

func s3ActionStrings(action interface{}) []string {
	switch a := action.(type) {
	case string:
		return []string{a}
	case []interface{}:
		var out []string
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func s3ResourceStrings(resource interface{}) []string {
	switch r := resource.(type) {
	case string:
		return []string{r}
	case []interface{}:
		var out []string
		for _, value := range r {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func s3PrincipalIsPublic(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]interface{}:
		for _, v := range p {
			switch t := v.(type) {
			case string:
				if t == "*" {
					return true
				}
			case []interface{}:
				for _, item := range t {
					if s, ok := item.(string); ok && s == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func s3PrincipalValues(principal interface{}) []string {
	var values []string
	switch p := principal.(type) {
	case nil:
		return nil
	case string:
		values = append(values, p)
	case []interface{}:
		for _, value := range p {
			if s, ok := value.(string); ok {
				values = append(values, s)
			}
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(p))
		for key := range p {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			values = append(values, s3PrincipalValues(p[key])...)
		}
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := strings.TrimSpace(strings.ToLower(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func s3PolicyNotMorePermissive(bucketPolicy, controlPolicy string) (bool, string) {
	bucketStatements, err := s3PolicyStatements(bucketPolicy)
	if err != nil {
		return false, "Invalid bucket policy document"
	}
	controlStatements, err := s3PolicyStatements(controlPolicy)
	if err != nil {
		return false, "Invalid control policy document"
	}

	controlAllows := make([]s3PolicyStatement, 0, len(controlStatements))
	for _, statement := range controlStatements {
		if strings.EqualFold(statement.Effect, "Allow") {
			controlAllows = append(controlAllows, statement)
		}
	}

	for _, statement := range bucketStatements {
		if !strings.EqualFold(statement.Effect, "Allow") {
			continue
		}
		if s3AllowStatementCoveredByControl(statement, controlAllows) {
			continue
		}
		return false, "Bucket policy allows actions/resources outside control policy"
	}
	return true, "Bucket allow statements are not more permissive than control policy"
}

func s3AllowStatementCoveredByControl(statement s3PolicyStatement, controlAllows []s3PolicyStatement) bool {
	stmtPrincipals := s3PrincipalValues(statement.Principal)
	stmtActions := normalizePolicyStrings(s3ActionStrings(statement.Action))
	stmtResources := normalizePolicyStrings(s3ResourceStrings(statement.Resource))

	for _, controlStatement := range controlAllows {
		if !s3PrincipalSetCovered(stmtPrincipals, s3PrincipalValues(controlStatement.Principal)) {
			continue
		}
		if !s3StringSetCovered(stmtActions, normalizePolicyStrings(s3ActionStrings(controlStatement.Action))) {
			continue
		}
		if !s3StringSetCovered(stmtResources, normalizePolicyStrings(s3ResourceStrings(controlStatement.Resource))) {
			continue
		}
		if !s3ConditionCompatible(statement.Condition, controlStatement.Condition) {
			continue
		}
		return true
	}
	return false
}

func normalizePolicyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := strings.TrimSpace(strings.ToLower(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func s3PrincipalSetCovered(values, allowed []string) bool {
	if len(values) == 0 {
		return len(allowed) == 0
	}
	if len(allowed) == 0 {
		return false
	}
	for _, value := range values {
		covered := false
		for _, allow := range allowed {
			if allow == "*" || allow == value {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func s3StringSetCovered(values, allowedPatterns []string) bool {
	if len(values) == 0 {
		return len(allowedPatterns) == 0
	}
	if len(allowedPatterns) == 0 {
		return false
	}
	for _, value := range values {
		if !s3MatchesAnyPattern(value, allowedPatterns) {
			return false
		}
	}
	return true
}

func s3MatchesAnyPattern(value string, patterns []string) bool {
	for _, patternValue := range patterns {
		if patternValue == "*" || patternValue == value {
			return true
		}
		matched, err := path.Match(patternValue, value)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func s3ConditionCompatible(statementCondition, controlCondition map[string]any) bool {
	if len(controlCondition) == 0 {
		return true
	}
	if len(statementCondition) == 0 {
		return false
	}
	return reflect.DeepEqual(statementCondition, controlCondition)
}

func s3PolicyAllowsPublicWrite(policy string) bool {
	statements, err := s3PolicyStatements(policy)
	if err != nil {
		return false
	}
	writeActionPatterns := []string{
		"*",
		"s3:*",
		"s3:put*",
		"s3:replicate*",
		"s3:deleteobject*",
		"s3:abortmultipartupload",
		"s3:objectowneroverride*",
	}
	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") || !s3PrincipalIsPublic(st.Principal) {
			continue
		}
		for _, a := range s3ActionStrings(st.Action) {
			la := strings.ToLower(strings.TrimSpace(a))
			if s3MatchesAnyPattern(la, writeActionPatterns) {
				return true
			}
		}
	}
	return false
}

func s3ACLAllowsPublicWrite(acl *s3.GetBucketAclOutput) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.Grants {
		if grant.Grantee == nil || grant.Grantee.URI == nil {
			continue
		}
		uri := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*grant.Grantee.URI)), "/")
		publicGroup := uri == "http://acs.amazonaws.com/groups/global/allusers" ||
			uri == "https://acs.amazonaws.com/groups/global/allusers" ||
			uri == "http://acs.amazonaws.com/groups/global/authenticatedusers" ||
			uri == "https://acs.amazonaws.com/groups/global/authenticatedusers"
		if !publicGroup {
			continue
		}
		perm := strings.ToUpper(string(grant.Permission))
		if perm == "WRITE" || perm == "FULL_CONTROL" {
			return true
		}
	}
	return false
}

func s3OnlyOwnerHasACL(acl *s3.GetBucketAclOutput) bool {
	if acl == nil || acl.Owner == nil || acl.Owner.ID == nil {
		return false
	}
	ownerID := *acl.Owner.ID
	for _, grant := range acl.Grants {
		if grant.Grantee == nil {
			return false
		}
		if grant.Grantee.Type != s3types.TypeCanonicalUser {
			return false
		}
		if grant.Grantee.ID == nil || *grant.Grantee.ID != ownerID {
			return false
		}
	}
	return true
}
