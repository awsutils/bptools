package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterEvidentlyChecks registers Evidently checks.
func RegisterEvidentlyChecks(d *awsdata.Data) {
	checker.Register(DescriptionCheck(
		"evidently-launch-description",
		"This rule checks evidently launch description.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			launches, err := d.EvidentlyLaunchDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for arn, l := range launches {
				has := l.Description != nil && *l.Description != ""
				res = append(res, DescriptionResource{ID: arn, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"evidently-launch-tagged",
		"This rule checks tagging for evidently launch exist.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			launches, err := d.EvidentlyLaunchDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.EvidentlyLaunchTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range launches {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"evidently-project-description",
		"This rule checks evidently project description.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			projects, err := d.EvidentlyProjectDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for arn, p := range projects {
				has := p.Description != nil && *p.Description != ""
				res = append(res, DescriptionResource{ID: arn, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"evidently-project-tagged",
		"This rule checks tagging for evidently project exist.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			projects, err := d.EvidentlyProjectDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.EvidentlyProjectTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range projects {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"evidently-segment-description",
		"This rule checks evidently segment description.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			segments, err := d.EvidentlySegmentDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for arn, s := range segments {
				has := s.Description != nil && *s.Description != ""
				res = append(res, DescriptionResource{ID: arn, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"evidently-segment-tagged",
		"This rule checks tagging for evidently segment exist.",
		"evidently",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			segments, err := d.EvidentlySegmentDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.EvidentlySegmentTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range segments {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))
}
