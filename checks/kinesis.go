package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterKinesisChecks registers Kinesis checks.
func RegisterKinesisChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"kinesis-stream-encrypted",
		"This rule checks Kinesis stream encrypted.",
		"kinesis",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			details, err := d.KinesisStreamDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, desc := range details {
				encrypted := desc.StreamDescription != nil && desc.StreamDescription.EncryptionType != "NONE"
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"kinesis-stream-backup-retention-check",
		"This rule checks Kinesis stream backup retention.",
		"kinesis",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			details, err := d.KinesisStreamDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, desc := range details {
				hours := int32(0)
				if desc.StreamDescription != nil && desc.StreamDescription.RetentionPeriodHours != nil {
					hours = *desc.StreamDescription.RetentionPeriodHours
				}
				ok := hours > 24
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: "Retention > 24h"})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"kinesis-firehose-delivery-stream-encrypted",
		"This rule checks Kinesis Firehose delivery stream encrypted.",
		"firehose",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			streams, err := d.FirehoseDeliveryDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, s := range streams {
				encrypted := s.DeliveryStreamEncryptionConfiguration != nil && s.DeliveryStreamEncryptionConfiguration.Status != "DISABLED"
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"kinesis-video-stream-minimum-data-retention",
		"This rule checks Kinesis video stream minimum data retention.",
		"kinesisvideo",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			streams, err := d.KinesisVideoStreams.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range streams {
				id := "unknown"
				if s.StreamARN != nil {
					id = *s.StreamARN
				}
				ok := s.DataRetentionInHours != nil && *s.DataRetentionInHours >= 24
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Retention >= 24h"})
			}
			return res, nil
		},
	))
}
