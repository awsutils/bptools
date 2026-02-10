package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterLightsailChecks registers Lightsail checks.
func RegisterLightsailChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"lightsail-bucket-allow-public-overrides-disabled",
		"This rule checks disabled state for lightsail bucket allow public overrides.",
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
		"This rule checks tagging for lightsail bucket exist.",
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
		"This rule checks tagging for lightsail certificate exist.",
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
		"This rule checks tagging for lightsail disk exist.",
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
