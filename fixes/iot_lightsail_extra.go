package fixes

import (
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

type iotAuthorizerTokenSigningFix struct{ clients *awsdata.Clients }

func (f *iotAuthorizerTokenSigningFix) CheckID() string {
	return "iot-authorizer-token-signing-enabled"
}
func (f *iotAuthorizerTokenSigningFix) Description() string {
	return "Enable token signing validation on IoT authorizer"
}
func (f *iotAuthorizerTokenSigningFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *iotAuthorizerTokenSigningFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *iotAuthorizerTokenSigningFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	name := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing authorizer name"
		return base
	}

	out, err := f.clients.IoT.DescribeAuthorizer(fctx.Ctx, &iot.DescribeAuthorizerInput{
		AuthorizerName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe authorizer: " + err.Error()
		return base
	}
	if out.AuthorizerDescription == nil {
		base.Status = fix.FixFailed
		base.Message = "authorizer not found"
		return base
	}
	if out.AuthorizerDescription.SigningDisabled == nil || !*out.AuthorizerDescription.SigningDisabled {
		base.Status = fix.FixSkipped
		base.Message = "token signing validation already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set IoT authorizer status ACTIVE to enforce token signing validation"}
		return base
	}

	_, err = f.clients.IoT.UpdateAuthorizer(fctx.Ctx, &iot.UpdateAuthorizerInput{
		AuthorizerName:         aws.String(name),
		AuthorizerFunctionArn:  out.AuthorizerDescription.AuthorizerFunctionArn,
		TokenKeyName:           out.AuthorizerDescription.TokenKeyName,
		TokenSigningPublicKeys: out.AuthorizerDescription.TokenSigningPublicKeys,
		Status:                 iottypes.AuthorizerStatusActive,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update authorizer: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"enabled token signing validation on IoT authorizer " + name}
	return base
}

type lightsailBucketPublicOverridesFix struct{ clients *awsdata.Clients }

func (f *lightsailBucketPublicOverridesFix) CheckID() string {
	return "lightsail-bucket-allow-public-overrides-disabled"
}
func (f *lightsailBucketPublicOverridesFix) Description() string {
	return "Disable Lightsail bucket allow public overrides"
}
func (f *lightsailBucketPublicOverridesFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *lightsailBucketPublicOverridesFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *lightsailBucketPublicOverridesFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing bucket ID"
		return base
	}

	buckets, err := f.clients.Lightsail.GetBuckets(fctx.Ctx, &lightsail.GetBucketsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get buckets: " + err.Error()
		return base
	}

	bucketName := ""
	alreadyDisabled := false
	for _, b := range buckets.Buckets {
		if b.Arn != nil && *b.Arn == id && b.Name != nil {
			bucketName = *b.Name
			alreadyDisabled = b.AccessRules != nil && b.AccessRules.AllowPublicOverrides != nil && !*b.AccessRules.AllowPublicOverrides
			break
		}
	}
	if bucketName == "" {
		base.Status = fix.FixFailed
		base.Message = "bucket not found by ARN"
		return base
	}
	if alreadyDisabled {
		base.Status = fix.FixSkipped
		base.Message = "allow public overrides already disabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would disable allow public overrides on Lightsail bucket " + bucketName}
		return base
	}

	_, err = f.clients.Lightsail.UpdateBucket(fctx.Ctx, &lightsail.UpdateBucketInput{
		BucketName: aws.String(bucketName),
		AccessRules: &lightsailtypes.AccessRules{
			AllowPublicOverrides: aws.Bool(false),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update bucket: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"disabled allow public overrides on Lightsail bucket " + bucketName}
	return base
}
