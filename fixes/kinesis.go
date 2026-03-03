package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

// ── kinesis-stream-backup-retention-check ─────────────────────────────────────

const kinesisMinRetentionHours = int32(168) // 7 days

type kinesisRetentionFix struct{ clients *awsdata.Clients }

func (f *kinesisRetentionFix) CheckID() string {
	return "kinesis-stream-backup-retention-check"
}
func (f *kinesisRetentionFix) Description() string {
	return "Increase Kinesis stream retention period to 168 hours (7 days)"
}
func (f *kinesisRetentionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *kinesisRetentionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *kinesisRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Kinesis.DescribeStream(fctx.Ctx, &kinesis.DescribeStreamInput{
		StreamName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe stream: " + err.Error()
		return base
	}
	if out.StreamDescription != nil && out.StreamDescription.RetentionPeriodHours != nil &&
		*out.StreamDescription.RetentionPeriodHours >= kinesisMinRetentionHours {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("retention already %d hours", *out.StreamDescription.RetentionPeriodHours)
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would increase Kinesis stream %s retention to %d hours", resourceID, kinesisMinRetentionHours)}
		return base
	}

	_, err = f.clients.Kinesis.IncreaseStreamRetentionPeriod(fctx.Ctx, &kinesis.IncreaseStreamRetentionPeriodInput{
		StreamName:           aws.String(resourceID),
		RetentionPeriodHours: aws.Int32(kinesisMinRetentionHours),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "increase stream retention: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("increased Kinesis stream %s retention to %d hours", resourceID, kinesisMinRetentionHours)}
	base.Status = fix.FixApplied
	return base
}

// ── kinesis-stream-encrypted ──────────────────────────────────────────────────

type kinesisEncryptionFix struct{ clients *awsdata.Clients }

func (f *kinesisEncryptionFix) CheckID() string     { return "kinesis-stream-encrypted" }
func (f *kinesisEncryptionFix) Description() string { return "Enable server-side encryption on Kinesis stream" }
func (f *kinesisEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *kinesisEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *kinesisEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Kinesis.DescribeStream(fctx.Ctx, &kinesis.DescribeStreamInput{
		StreamName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe stream: " + err.Error()
		return base
	}
	if out.StreamDescription != nil && out.StreamDescription.EncryptionType != kinesistypes.EncryptionTypeNone {
		base.Status = fix.FixSkipped
		base.Message = "stream encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable server-side encryption on Kinesis stream %s (key: aws/kinesis)", resourceID)}
		return base
	}

	_, err = f.clients.Kinesis.StartStreamEncryption(fctx.Ctx, &kinesis.StartStreamEncryptionInput{
		StreamName:     aws.String(resourceID),
		EncryptionType: kinesistypes.EncryptionTypeKms,
		KeyId:          aws.String("aws/kinesis"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "start stream encryption: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled server-side encryption on Kinesis stream %s (key: aws/kinesis)", resourceID)}
	base.Status = fix.FixApplied
	return base
}
