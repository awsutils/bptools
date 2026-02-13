package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterLightsailChecks registers Lightsail checks.
func RegisterLightsailChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"lightsail-bucket-allow-public-overrides-disabled",
		"Checks if Amazon Lightsail buckets have allow public overrides disabled. The rule is NON_COMPLIANT if AllowPublicOverrides is true. Note: AllowPublicOverrides has no effect if GetObject is public, see lightsail-bucket-get-object-private.",
		"lightsail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			buckets, err := d.LightsailBuckets.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, b := range buckets {
				id := "unknown"
				if b.Arn != nil {
					id = *b.Arn
				}
				enabled := b.AccessRules != nil && b.AccessRules.AllowPublicOverrides != nil && !*b.AccessRules.AllowPublicOverrides
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"lightsail-bucket-tagged",
		"Checks if Amazon Lightsail buckets have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"lightsail",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			buckets, err := d.LightsailBuckets.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, b := range buckets {
				id := "unknown"
				if b.Arn != nil {
					id = *b.Arn
				}
				tags := make(map[string]string)
				for _, t := range b.Tags {
					if t.Key != nil && t.Value != nil {
						tags[*t.Key] = *t.Value
					}
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"lightsail-certificate-tagged",
		"Checks if Amazon Lightsail certificates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"lightsail",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.LightsailCertificates.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.CertificateArn != nil {
					id = *it.CertificateArn
				}
				tags := make(map[string]string)
				for _, t := range it.Tags {
					if t.Key != nil && t.Value != nil {
						tags[*t.Key] = *t.Value
					}
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"lightsail-disk-tagged",
		"Checks if Amazon Lightsail disks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"lightsail",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.LightsailDisks.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Arn != nil {
					id = *it.Arn
				}
				tags := make(map[string]string)
				for _, t := range it.Tags {
					if t.Key != nil && t.Value != nil {
						tags[*t.Key] = *t.Value
					}
				}
				res = append(res, TaggedResource{ID: id, Tags: tags})
			}
			return res, nil
		},
	))
}
