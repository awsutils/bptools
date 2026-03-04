package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// ── sns-encrypted-kms ─────────────────────────────────────────────────────────

type snsKMSEncryptionFix struct{ clients *awsdata.Clients }

func (f *snsKMSEncryptionFix) CheckID() string          { return "sns-encrypted-kms" }
func (f *snsKMSEncryptionFix) Description() string      { return "Enable KMS encryption on SNS topic" }
func (f *snsKMSEncryptionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *snsKMSEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *snsKMSEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.SNS.GetTopicAttributes(fctx.Ctx, &sns.GetTopicAttributesInput{
		TopicArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get topic attributes: " + err.Error()
		return base
	}
	if attrOut.Attributes["KmsMasterKeyId"] != "" {
		base.Status = fix.FixSkipped
		base.Message = "KMS encryption already configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable KMS encryption on SNS topic %s", resourceID)}
		return base
	}

	_, err = f.clients.SNS.SetTopicAttributes(fctx.Ctx, &sns.SetTopicAttributesInput{
		TopicArn:       aws.String(resourceID),
		AttributeName:  aws.String("KmsMasterKeyId"),
		AttributeValue: aws.String("alias/aws/sns"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set topic attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled KMS encryption (alias/aws/sns) on SNS topic %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── sns-topic-no-public-access ────────────────────────────────────────────────

type snsNoPublicAccessFix struct{ clients *awsdata.Clients }

func (f *snsNoPublicAccessFix) CheckID() string { return "sns-topic-no-public-access" }
func (f *snsNoPublicAccessFix) Description() string {
	return "Remove public Allow statements from SNS topic policy"
}
func (f *snsNoPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *snsNoPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *snsNoPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	attrOut, err := f.clients.SNS.GetTopicAttributes(fctx.Ctx, &sns.GetTopicAttributesInput{
		TopicArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get topic attributes: " + err.Error()
		return base
	}

	currentPolicy := attrOut.Attributes["Policy"]
	newPolicy, changed, err := removePublicAllowStatements(currentPolicy)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "parse topic policy: " + err.Error()
		return base
	}
	if !changed {
		base.Status = fix.FixSkipped
		base.Message = "SNS topic policy has no public Allow statements"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove public Allow statements from SNS topic %s policy", resourceID)}
		return base
	}

	_, err = f.clients.SNS.SetTopicAttributes(fctx.Ctx, &sns.SetTopicAttributesInput{
		TopicArn:       aws.String(resourceID),
		AttributeName:  aws.String("Policy"),
		AttributeValue: aws.String(newPolicy),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "set topic attributes: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed public Allow statements from SNS topic %s policy", resourceID)}
	base.Status = fix.FixApplied
	return base
}
