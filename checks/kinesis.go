package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterKinesisChecks registers Kinesis checks.
func RegisterKinesisChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"kinesis-stream-encrypted",
		"Checks if Amazon Kinesis streams are encrypted at rest with server-side encryption. The rule is NON_COMPLIANT for a Kinesis stream if 'StreamEncryption' is not present.",
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
		"Checks if an Amazon Kinesis Data Stream has its data record retention period set to a specific number of hours. The rule is NON_COMPLIANT if the property `RetentionPeriodHours` is set to a value less than the value specified by the parameter.",
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
				ok := hours >= 168
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Retention hours: %d", hours)})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"kinesis-firehose-delivery-stream-encrypted",
		"Checks if Amazon Kinesis Data Firehose delivery streams are encrypted at rest with server-side encryption. The rule is NON_COMPLIANT if a Kinesis Data Firehose delivery stream is not encrypted at rest with server-side encryption.",
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
		"Checks if an Amazon Kinesis Video stream is configured with a value greater than or equal to the specified minimum data retention. The rule is NON_COMPLIANT if DataRetentionInHours is less than the value specified in the required rule parameter.",
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
