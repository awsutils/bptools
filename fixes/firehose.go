package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
)

// ── kinesis-firehose-delivery-stream-encrypted ────────────────────────────────

type firehoseEncryptionFix struct{ clients *awsdata.Clients }

func (f *firehoseEncryptionFix) CheckID() string {
	return "kinesis-firehose-delivery-stream-encrypted"
}
func (f *firehoseEncryptionFix) Description() string {
	return "Enable server-side encryption on Kinesis Firehose delivery stream"
}
func (f *firehoseEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *firehoseEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *firehoseEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Firehose.DescribeDeliveryStream(fctx.Ctx, &firehose.DescribeDeliveryStreamInput{
		DeliveryStreamName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe delivery stream: " + err.Error()
		return base
	}
	if out.DeliveryStreamDescription == nil {
		base.Status = fix.FixFailed
		base.Message = "delivery stream not found: " + resourceID
		return base
	}
	enc := out.DeliveryStreamDescription.DeliveryStreamEncryptionConfiguration
	if enc != nil && enc.Status != firehosetypes.DeliveryStreamEncryptionStatusDisabled {
		base.Status = fix.FixSkipped
		base.Message = "encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable SSE on Firehose delivery stream " + resourceID}
		return base
	}

	_, err = f.clients.Firehose.StartDeliveryStreamEncryption(fctx.Ctx, &firehose.StartDeliveryStreamEncryptionInput{
		DeliveryStreamName: aws.String(resourceID),
		DeliveryStreamEncryptionConfigurationInput: &firehosetypes.DeliveryStreamEncryptionConfigurationInput{
			KeyType: firehosetypes.KeyTypeAwsOwnedCmk,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start delivery stream encryption: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled SSE (AWS-owned CMK) on Firehose delivery stream " + resourceID}
	base.Status = fix.FixApplied
	return base
}
