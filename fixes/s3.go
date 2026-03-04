package fixes

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"
	"bptools/fix/pool"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ── s3-bucket-versioning-enabled ─────────────────────────────────────────────

type s3VersioningFix struct{ clients *awsdata.Clients }

func (f *s3VersioningFix) CheckID() string          { return "s3-bucket-versioning-enabled" }
func (f *s3VersioningFix) Description() string      { return "Enable S3 bucket versioning" }
func (f *s3VersioningFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *s3VersioningFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *s3VersioningFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.S3.GetBucketVersioning(fctx.Ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(resourceID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get bucket versioning: " + err.Error()
		return base
	}
	if out.Status == s3types.BucketVersioningStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "versioning already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable versioning on bucket %s", resourceID)}
		return base
	}

	_, err = f.clients.S3.PutBucketVersioning(fctx.Ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(resourceID),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket versioning: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled versioning on bucket %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── s3-bucket-server-side-encryption-enabled ─────────────────────────────────

type s3EncryptionFix struct{ clients *awsdata.Clients }

func (f *s3EncryptionFix) CheckID() string          { return "s3-bucket-server-side-encryption-enabled" }
func (f *s3EncryptionFix) Description() string      { return "Enable S3 default server-side encryption (AES-256)" }
func (f *s3EncryptionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *s3EncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *s3EncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	_, err := f.clients.S3.GetBucketEncryption(fctx.Ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(resourceID)})
	if err == nil {
		base.Status = fix.FixSkipped
		base.Message = "default encryption already configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable AES-256 default encryption on bucket %s", resourceID)}
		return base
	}

	_, err = f.clients.S3.PutBucketEncryption(fctx.Ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(resourceID),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryptionAes256,
				},
			}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket encryption: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled AES-256 default encryption on bucket %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

type s3LoggingFix struct {
	clients *awsdata.Clients
	pool    *pool.S3BucketPool
}

func newS3LoggingFix(clients *awsdata.Clients, p *pool.S3BucketPool) *s3LoggingFix {
	return &s3LoggingFix{clients: clients, pool: p}
}

func (f *s3LoggingFix) CheckID() string          { return "s3-bucket-logging-enabled" }
func (f *s3LoggingFix) Description() string      { return "Enable S3 server access logging" }
func (f *s3LoggingFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *s3LoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *s3LoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{
		CheckID:    f.CheckID(),
		ResourceID: resourceID,
		Impact:     f.Impact(),
		Severity:   f.Severity(),
	}

	// Idempotency: skip if logging is already configured.
	logOut, err := f.clients.S3.GetBucketLogging(fctx.Ctx, &s3.GetBucketLoggingInput{
		Bucket: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get bucket logging: " + err.Error()
		return base
	}
	if logOut.LoggingEnabled != nil {
		base.Status = fix.FixSkipped
		base.Message = "logging already enabled"
		return base
	}

	// Determine the bucket's region to ensure the logging bucket is co-located.
	locOut, err := f.clients.S3.GetBucketLocation(fctx.Ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get bucket location: " + err.Error()
		return base
	}
	region := string(locOut.LocationConstraint)
	if region == "" {
		region = "us-east-1" // empty constraint means us-east-1
	}

	targetBucket, steps, err := f.pool.Ensure(fctx.Ctx, pool.S3BucketSpec{
		Purpose:        "service-logs",
		Region:         region,
		BucketPrefix:   "logs-",
		BucketPolicyFn: serviceLogsBucketPolicy,
	}, fctx.DryRun)
	base.Steps = append(base.Steps, steps...)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "ensure logging bucket: " + err.Error()
		return base
	}

	prefix := "s3-access-logs/" + resourceID + "/"

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = append(base.Steps,
			fmt.Sprintf("would enable server access logging on %s → s3://%s/%s", resourceID, targetBucket, prefix),
		)
		return base
	}

	_, err = f.clients.S3.PutBucketLogging(fctx.Ctx, &s3.PutBucketLoggingInput{
		Bucket: aws.String(resourceID),
		BucketLoggingStatus: &s3types.BucketLoggingStatus{
			LoggingEnabled: &s3types.LoggingEnabled{
				TargetBucket: aws.String(targetBucket),
				TargetPrefix: aws.String(prefix),
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket logging: " + err.Error()
		return base
	}

	base.Steps = append(base.Steps,
		fmt.Sprintf("enabled server access logging on %s → s3://%s/%s", resourceID, targetBucket, prefix),
	)
	base.Status = fix.FixApplied
	return base
}

// ── s3-bucket-level-public-access-prohibited / s3-bucket-public-read-prohibited
// ── s3-bucket-public-write-prohibited ────────────────────────────────────────
//
// All three checks are fixed by enabling all four S3 Block Public Access
// settings on the bucket. A single fix struct is parameterised by checkID.

type s3PublicAccessBlockFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *s3PublicAccessBlockFix) CheckID() string          { return f.checkID }
func (f *s3PublicAccessBlockFix) Description() string      { return "Enable all S3 block-public-access settings on bucket" }
func (f *s3PublicAccessBlockFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *s3PublicAccessBlockFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *s3PublicAccessBlockFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.S3.GetPublicAccessBlock(fctx.Ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(resourceID)})
	if err == nil && out.PublicAccessBlockConfiguration != nil {
		cfg := out.PublicAccessBlockConfiguration
		allBlocked := cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
			cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
			cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
			cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
		if allBlocked {
			base.Status = fix.FixSkipped
			base.Message = "all public access block settings already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable all block-public-access settings on bucket %s", resourceID)}
		return base
	}

	_, err = f.clients.S3.PutPublicAccessBlock(fctx.Ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(resourceID),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put public access block: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled all block-public-access settings on bucket %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── s3-account-level-public-access-blocks / s3-account-level-public-access-blocks-periodic

type s3AccountPublicAccessBlockFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *s3AccountPublicAccessBlockFix) CheckID() string          { return f.checkID }
func (f *s3AccountPublicAccessBlockFix) Description() string      { return "Enable all S3 account-level block-public-access settings" }
func (f *s3AccountPublicAccessBlockFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *s3AccountPublicAccessBlockFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *s3AccountPublicAccessBlockFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.S3Control.GetPublicAccessBlock(fctx.Ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(resourceID),
	})
	if err == nil && out.PublicAccessBlockConfiguration != nil {
		cfg := out.PublicAccessBlockConfiguration
		allBlocked := cfg.BlockPublicAcls != nil && *cfg.BlockPublicAcls &&
			cfg.IgnorePublicAcls != nil && *cfg.IgnorePublicAcls &&
			cfg.BlockPublicPolicy != nil && *cfg.BlockPublicPolicy &&
			cfg.RestrictPublicBuckets != nil && *cfg.RestrictPublicBuckets
		if allBlocked {
			base.Status = fix.FixSkipped
			base.Message = "account-level public access block already fully enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable all account-level S3 block-public-access settings"}
		return base
	}

	_, err = f.clients.S3Control.PutPublicAccessBlock(fctx.Ctx, &s3control.PutPublicAccessBlockInput{
		AccountId: aws.String(resourceID),
		PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put account public access block: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled all account-level S3 block-public-access settings"}
	base.Status = fix.FixApplied
	return base
}

// ── s3-bucket-ssl-requests-only ──────────────────────────────────────────────

type s3SSLOnlyFix struct{ clients *awsdata.Clients }

func (f *s3SSLOnlyFix) CheckID() string          { return "s3-bucket-ssl-requests-only" }
func (f *s3SSLOnlyFix) Description() string      { return "Add deny-HTTP policy statement to S3 bucket" }
func (f *s3SSLOnlyFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *s3SSLOnlyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *s3SSLOnlyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	var existingPolicy string
	polOut, err := f.clients.S3.GetBucketPolicy(fctx.Ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(resourceID),
	})
	if err != nil {
		// NoSuchBucketPolicy is expected — bucket has no policy yet
		if !strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			base.Status = fix.FixFailed
			base.Message = "get bucket policy: " + err.Error()
			return base
		}
	} else if polOut.Policy != nil {
		existingPolicy = *polOut.Policy
	}

	// Idempotency: if there's already a SecureTransport deny statement, skip
	if strings.Contains(existingPolicy, "aws:SecureTransport") {
		base.Status = fix.FixSkipped
		base.Message = "bucket policy already denies insecure transport"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would add deny-HTTP policy statement to S3 bucket %s", resourceID)}
		return base
	}

	// Build the deny-insecure-transport statement
	denyStmt := map[string]interface{}{
		"Sid":       "DenyInsecureTransport",
		"Effect":    "Deny",
		"Principal": "*",
		"Action":    "s3:*",
		"Resource": []string{
			"arn:aws:s3:::" + resourceID,
			"arn:aws:s3:::" + resourceID + "/*",
		},
		"Condition": map[string]interface{}{
			"Bool": map[string]string{
				"aws:SecureTransport": "false",
			},
		},
	}

	var newPolicy string
	if existingPolicy == "" {
		// Create new policy
		pol := map[string]interface{}{
			"Version":   "2012-10-17",
			"Statement": []interface{}{denyStmt},
		}
		b, err := json.Marshal(pol)
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "marshal policy: " + err.Error()
			return base
		}
		newPolicy = string(b)
	} else {
		// Append to existing policy
		var pol map[string]interface{}
		if err := json.Unmarshal([]byte(existingPolicy), &pol); err != nil {
			base.Status = fix.FixFailed
			base.Message = "parse existing policy: " + err.Error()
			return base
		}
		stmts, _ := pol["Statement"].([]interface{})
		pol["Statement"] = append(stmts, denyStmt)
		b, err := json.Marshal(pol)
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "marshal updated policy: " + err.Error()
			return base
		}
		newPolicy = string(b)
	}

	_, err = f.clients.S3.PutBucketPolicy(fctx.Ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(resourceID),
		Policy: aws.String(newPolicy),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket policy: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("added deny-HTTP policy statement to S3 bucket %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── s3-default-encryption-kms ─────────────────────────────────────────────────

type s3KMSEncryptionFix struct{ clients *awsdata.Clients }

func (f *s3KMSEncryptionFix) CheckID() string { return "s3-default-encryption-kms" }
func (f *s3KMSEncryptionFix) Description() string {
	return "Enable S3 default SSE-KMS encryption on bucket"
}
func (f *s3KMSEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *s3KMSEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *s3KMSEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.S3.GetBucketEncryption(fctx.Ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(resourceID),
	})
	if err == nil && out.ServerSideEncryptionConfiguration != nil {
		for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault != nil &&
				rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm == s3types.ServerSideEncryptionAwsKms {
				base.Status = fix.FixSkipped
				base.Message = "SSE-KMS encryption already configured"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable SSE-KMS encryption on bucket %s", resourceID)}
		return base
	}

	_, err = f.clients.S3.PutBucketEncryption(fctx.Ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(resourceID),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryptionAwsKms,
				},
				BucketKeyEnabled: aws.Bool(true),
			}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket encryption: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled SSE-KMS encryption on bucket %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── s3-bucket-acl-prohibited ──────────────────────────────────────────────────

type s3ACLProhibitedFix struct{ clients *awsdata.Clients }

func (f *s3ACLProhibitedFix) CheckID() string { return "s3-bucket-acl-prohibited" }
func (f *s3ACLProhibitedFix) Description() string {
	return "Disable ACLs on S3 bucket by enabling BucketOwnerEnforced ownership"
}
func (f *s3ACLProhibitedFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *s3ACLProhibitedFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *s3ACLProhibitedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.S3.GetBucketOwnershipControls(fctx.Ctx, &s3.GetBucketOwnershipControlsInput{
		Bucket: aws.String(resourceID),
	})
	if err == nil && out.OwnershipControls != nil {
		for _, rule := range out.OwnershipControls.Rules {
			if rule.ObjectOwnership == s3types.ObjectOwnershipBucketOwnerEnforced {
				base.Status = fix.FixSkipped
				base.Message = "bucket already uses BucketOwnerEnforced (ACLs disabled)"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set BucketOwnerEnforced on bucket %s to disable ACLs", resourceID)}
		return base
	}

	_, err = f.clients.S3.PutBucketOwnershipControls(fctx.Ctx, &s3.PutBucketOwnershipControlsInput{
		Bucket: aws.String(resourceID),
		OwnershipControls: &s3types.OwnershipControls{
			Rules: []s3types.OwnershipControlsRule{{
				ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced,
			}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put bucket ownership controls: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set BucketOwnerEnforced on bucket %s (ACLs disabled)", resourceID)}
	base.Status = fix.FixApplied
	return base
}
