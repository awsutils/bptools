package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// RegisterCloudTrailChecks registers CloudTrail checks.
func RegisterCloudTrailChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"cloudtrail-enabled",
		"This rule checks enabled state for CloudTrail.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, st := range statuses {
				enabled := st.IsLogging != nil && *st.IsLogging
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-cloud-watch-logs-enabled",
		"This rule checks enabled state for cloud trail cloud watch logs.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.CloudWatchLogsLogGroupArn != nil && *t.CloudWatchLogsLogGroupArn != ""
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-encryption-enabled",
		"This rule checks enabled state for cloud trail encryption.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.KmsKeyId != nil && *t.KmsKeyId != ""
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-log-file-validation-enabled",
		"This rule checks enabled state for cloud trail log file validation.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.LogFileValidationEnabled != nil && *t.LogFileValidationEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-security-trail-enabled",
		"This rule checks cloudtrail security trail enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, t := range trails {
				ok := t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail && t.IncludeGlobalServiceEvents != nil && *t.IncludeGlobalServiceEvents
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Multi-region with global service events"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-s3-dataevents-enabled",
		"This rule checks cloudtrail s3 dataevents enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, ev := range events {
				ok := hasS3DataEvents(ev.EventSelectors)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "S3 data events configured"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-all-read-s3-data-event-check",
		"This rule checks cloudtrail all read s3 data event check.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, ev := range events {
				ok := s3DataEventReadWrite(ev.EventSelectors, cloudtrailtypes.ReadWriteTypeReadOnly)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "S3 read data events"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-all-write-s3-data-event-check",
		"This rule checks cloudtrail all write s3 data event check.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, ev := range events {
				ok := s3DataEventReadWrite(ev.EventSelectors, cloudtrailtypes.ReadWriteTypeWriteOnly)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "S3 write data events"})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"cloudtrail-s3-bucket-access-logging",
		"This rule checks cloudtrail s3 bucket access logging.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for id, t := range trails {
				bucket := ""
				if t.S3BucketName != nil {
					bucket = *t.S3BucketName
				}
				if bucket == "" {
					res = append(res, LoggingResource{ID: id, Logging: false})
					continue
				}
				out, err := d.Clients.S3.GetBucketLogging(d.Ctx, &s3.GetBucketLoggingInput{Bucket: &bucket})
				logging := err == nil && out.LoggingEnabled != nil
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-s3-bucket-public-access-prohibited",
		"This rule checks cloudtrail s3 bucket public access prohibited.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, t := range trails {
				bucket := ""
				if t.S3BucketName != nil {
					bucket = *t.S3BucketName
				}
				if bucket == "" {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No bucket configured"})
					continue
				}
				out, err := d.Clients.S3.GetPublicAccessBlock(d.Ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
				blocked := err == nil && out.PublicAccessBlockConfiguration != nil &&
					out.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *out.PublicAccessBlockConfiguration.BlockPublicAcls &&
					out.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *out.PublicAccessBlockConfiguration.IgnorePublicAcls &&
					out.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *out.PublicAccessBlockConfiguration.BlockPublicPolicy &&
					out.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *out.PublicAccessBlockConfiguration.RestrictPublicBuckets
				res = append(res, ConfigResource{ID: id, Passing: blocked, Detail: fmt.Sprintf("Public access blocked: %v", blocked)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"event-data-store-cmk-encryption-enabled",
		"This rule checks event data store cmk encryption enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stores, err := d.CloudTrailEventDataStores.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range stores {
				id := "unknown"
				if s.EventDataStoreArn != nil {
					id = *s.EventDataStoreArn
				}
				// EventDataStore from ListEventDataStores does not include KmsKeyId.
				// Without DescribeEventDataStore, we cannot determine CMK encryption.
				ok := false
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "KmsKeyId not available from ListEventDataStores"})
			}
			return res, nil
		},
	))
}

func hasS3DataEvents(selectors []cloudtrailtypes.EventSelector) bool {
	for _, s := range selectors {
		for _, r := range s.DataResources {
			if r.Type != nil && strings.EqualFold(*r.Type, "AWS::S3::Object") {
				return true
			}
		}
	}
	return false
}

func s3DataEventReadWrite(selectors []cloudtrailtypes.EventSelector, want cloudtrailtypes.ReadWriteType) bool {
	for _, s := range selectors {
		for _, r := range s.DataResources {
			if r.Type == nil || !strings.EqualFold(*r.Type, "AWS::S3::Object") {
				continue
			}
			if s.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll || s.ReadWriteType == want {
				return true
			}
		}
	}
	return false
}
