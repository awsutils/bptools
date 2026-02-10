package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterTaggingChecks registers tag-related checks.
func RegisterTaggingChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"required-tags",
		"This rule checks required tags.",
		"tagging",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			mappings, err := d.ResourceTagMappings.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range mappings {
				id := "unknown"
				if m.ResourceARN != nil {
					id = *m.ResourceARN
				}
				tags := make(map[string]string)
				for _, t := range m.Tags {
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
