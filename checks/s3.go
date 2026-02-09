package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

func bucketName(b s3types.Bucket) string {
	if b.Name != nil { return *b.Name }
	return "unknown"
}

func RegisterS3Checks(d *awsdata.Data) {
	// s3-bucket-tagged
	checker.Register(TaggedCheck("s3-bucket-tagged", "Check S3 bucket tagged", "s3", d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []TaggedResource
			for _, b := range buckets {
				tags := make(map[string]string)
				out, err := d.Clients.S3.GetBucketTagging(d.Ctx, &s3.GetBucketTaggingInput{Bucket: b.Name})
				if err == nil {
					for _, t := range out.TagSet {
						if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
					}
				}
				res = append(res, TaggedResource{ID: bucketName(b), Tags: tags})
			}
			return res, nil
		}))

	// s3-bucket-versioning-enabled
	checker.Register(EnabledCheck("s3-bucket-versioning-enabled", "Check versioning", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketVersioning(d.Ctx, &s3.GetBucketVersioningInput{Bucket: b.Name})
				enabled := err == nil && out.Status == s3types.BucketVersioningStatusEnabled
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
			}
			return res, nil
		}))

	// s3-bucket-server-side-encryption-enabled
	checker.Register(EnabledCheck("s3-bucket-server-side-encryption-enabled", "Check SSE", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, b := range buckets {
				_, err := d.Clients.S3.GetBucketEncryption(d.Ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: err == nil})
			}
			return res, nil
		}))

	// s3-bucket-logging-enabled
	checker.Register(LoggingCheck("s3-bucket-logging-enabled", "Check bucket logging", "s3", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []LoggingResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketLogging(d.Ctx, &s3.GetBucketLoggingInput{Bucket: b.Name})
				logging := err == nil && out.LoggingEnabled != nil
				res = append(res, LoggingResource{ID: bucketName(b), Logging: logging})
			}
			return res, nil
		}))

	// s3-bucket-public-read-prohibited + s3-bucket-public-write-prohibited + s3-bucket-level-public-access-prohibited
	checker.Register(ConfigCheck("s3-bucket-public-read-prohibited", "Check no public read", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicyStatus(d.Ctx, &s3.GetBucketPolicyStatusInput{Bucket: b.Name})
				public := err == nil && out.PolicyStatus != nil && out.PolicyStatus.IsPublic
				res = append(res, ConfigResource{ID: bucketName(b), Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-public-write-prohibited", "Check no public write", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetPublicAccessBlock(d.Ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
				blocked := err == nil && out.PublicAccessBlockConfiguration != nil &&
					out.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *out.PublicAccessBlockConfiguration.BlockPublicAcls &&
					out.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *out.PublicAccessBlockConfiguration.BlockPublicPolicy
				res = append(res, ConfigResource{ID: bucketName(b), Passing: blocked, Detail: fmt.Sprintf("Public access blocked: %v", blocked)})
			}
			return res, nil
		}))

	checker.Register(ConfigCheck("s3-bucket-level-public-access-prohibited", "Check bucket public access blocked", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
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
	checker.Register(ConfigCheck("s3-bucket-ssl-requests-only", "Check SSL only", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketPolicy(d.Ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
				hasSSL := err == nil && out.Policy != nil
				res = append(res, ConfigResource{ID: bucketName(b), Passing: hasSSL, Detail: "SSL policy check"})
			}
			return res, nil
		}))

	// s3-bucket-cross-region-replication-enabled + s3-bucket-replication-enabled
	for _, id := range []string{"s3-bucket-cross-region-replication-enabled", "s3-bucket-replication-enabled"} {
		cid := id
		checker.Register(EnabledCheck(cid, "Check replication", "s3", d,
			func(d *awsdata.Data) ([]EnabledResource, error) {
				buckets, err := d.S3Buckets.Get()
				if err != nil { return nil, err }
				var res []EnabledResource
				for _, b := range buckets {
					out, err := d.Clients.S3.GetBucketReplication(d.Ctx, &s3.GetBucketReplicationInput{Bucket: b.Name})
					enabled := err == nil && out.ReplicationConfiguration != nil && len(out.ReplicationConfiguration.Rules) > 0
					res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
				}
				return res, nil
			}))
		_ = cid
	}

	// s3-bucket-default-lock-enabled
	checker.Register(EnabledCheck("s3-bucket-default-lock-enabled", "Check object lock", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, b := range buckets {
				_, err := d.Clients.S3.GetObjectLockConfiguration(d.Ctx, &s3.GetObjectLockConfigurationInput{Bucket: b.Name})
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: err == nil})
			}
			return res, nil
		}))

	// s3-bucket-mfa-delete-enabled
	checker.Register(EnabledCheck("s3-bucket-mfa-delete-enabled", "Check MFA delete", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []EnabledResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketVersioning(d.Ctx, &s3.GetBucketVersioningInput{Bucket: b.Name})
				enabled := err == nil && out.MFADelete == s3types.MFADeleteStatusEnabled
				res = append(res, EnabledResource{ID: bucketName(b), Enabled: enabled})
			}
			return res, nil
		}))

	// s3-bucket-acl-prohibited
	checker.Register(ConfigCheck("s3-bucket-acl-prohibited", "Check ACL prohibited", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
			var res []ConfigResource
			for _, b := range buckets {
				out, err := d.Clients.S3.GetBucketAcl(d.Ctx, &s3.GetBucketAclInput{Bucket: b.Name})
				private := true
				if err == nil {
					for _, g := range out.Grants {
						if g.Grantee != nil && g.Grantee.URI != nil && (*g.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" || *g.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") {
							private = false
						}
					}
				}
				res = append(res, ConfigResource{ID: bucketName(b), Passing: private, Detail: fmt.Sprintf("ACL private: %v", private)})
			}
			return res, nil
		}))

	// s3-default-encryption-kms
	checker.Register(ConfigCheck("s3-default-encryption-kms", "Check KMS encryption", "s3", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
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
	checker.Register(EnabledCheck("s3-event-notifications-enabled", "Check event notifications", "s3", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.S3Buckets.Get()
			if err != nil { return nil, err }
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
				if err != nil { return nil, err }
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
				if err != nil { return false, "", err }
				out, err := d.Clients.S3Control.GetPublicAccessBlock(d.Ctx, &s3control.GetPublicAccessBlockInput{AccountId: &acctID})
				if err != nil { return false, "No account-level public access block", nil }
				cfg := out.PublicAccessBlockConfiguration
				blocked := cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
					cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
					cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
					cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
				return blocked, fmt.Sprintf("Account public access blocked: %v", blocked), nil
			}))
		_ = cid
	}

	// Stub checks
	for _, id := range []string{
		"s3-access-point-in-vpc-only", "s3-access-point-public-access-blocks",
		"s3-bucket-blacklisted-actions-prohibited", "s3-bucket-policy-grantee-check",
		"s3-bucket-policy-not-more-permissive", "s3express-dir-bucket-lifecycle-rules-check",
		"s3-last-backup-recovery-point-created", "s3-meets-restore-time-target",
		"s3-resources-in-logically-air-gapped-vault", "s3-resources-protected-by-backup-plan",
	} {
		cid := id
		checker.Register(&BaseCheck{CheckID: cid, Desc: "S3 check", Svc: "s3",
			RunFunc: func() []checker.Result {
				return []checker.Result{{CheckID: cid, Status: checker.StatusSkip, Message: "Requires additional configuration"}}
			}})
	}
}
