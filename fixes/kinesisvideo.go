package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	kvsTypes "github.com/aws/aws-sdk-go-v2/service/kinesisvideo/types"
)

// ── kinesis-video-stream-minimum-data-retention ───────────────────────────────

const kvsMinRetentionHours = int32(24)

type kinesisVideoRetentionFix struct{ clients *awsdata.Clients }

func (f *kinesisVideoRetentionFix) CheckID() string {
	return "kinesis-video-stream-minimum-data-retention"
}
func (f *kinesisVideoRetentionFix) Description() string {
	return "Set Kinesis Video stream data retention to at least 24 hours"
}
func (f *kinesisVideoRetentionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *kinesisVideoRetentionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *kinesisVideoRetentionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.KinesisVideo.DescribeStream(fctx.Ctx, &kinesisvideo.DescribeStreamInput{
		StreamARN: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe stream: " + err.Error()
		return base
	}

	current := int32(0)
	if out.StreamInfo != nil && out.StreamInfo.DataRetentionInHours != nil {
		current = *out.StreamInfo.DataRetentionInHours
	}
	if current >= kvsMinRetentionHours {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("data retention already >= %d hours (current: %d)", kvsMinRetentionHours, current)
		return base
	}

	if out.StreamInfo == nil || out.StreamInfo.Version == nil {
		base.Status = fix.FixFailed
		base.Message = "stream info or version missing"
		return base
	}

	increaseBy := kvsMinRetentionHours - current

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would increase data retention by %d hours (to %d h) on Kinesis Video stream %s", increaseBy, kvsMinRetentionHours, resourceID),
		}
		return base
	}

	_, err = f.clients.KinesisVideo.UpdateDataRetention(fctx.Ctx, &kinesisvideo.UpdateDataRetentionInput{
		StreamARN:                  aws.String(resourceID),
		CurrentVersion:             out.StreamInfo.Version,
		DataRetentionChangeInHours: aws.Int32(increaseBy),
		Operation:                  kvsTypes.UpdateDataRetentionOperationIncreaseDataRetention,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update data retention: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("increased data retention by %d hours (to %d h) on Kinesis Video stream %s", increaseBy, kvsMinRetentionHours, resourceID),
	}
	base.Status = fix.FixApplied
	return base
}
