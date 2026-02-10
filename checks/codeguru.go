package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCodeGuruChecks registers CodeGuru checks.
func RegisterCodeGuruChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"codeguruprofiler-profiling-group-tagged",
		"This rule checks codeguruprofiler profiling group tagged.",
		"codeguruprofiler",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			groups, err := d.CodeGuruProfilingGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CodeGuruProfilerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, g := range groups {
				id := "unknown"
				tagKey := ""
				if g.Arn != nil {
					id = *g.Arn
					tagKey = *g.Arn
				} else if g.Name != nil {
					id = *g.Name
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[tagKey]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"codegurureviewer-repository-association-tagged",
		"This rule checks codegurureviewer repository association tagged.",
		"codegurureviewer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			assocs, err := d.CodeGuruReviewerAssociations.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CodeGuruReviewerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range assocs {
				id := "unknown"
				tagKey := ""
				if a.AssociationArn != nil {
					id = *a.AssociationArn
					tagKey = *a.AssociationArn
				} else if a.Name != nil {
					id = *a.Name
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[tagKey]})
			}
			return res, nil
		},
	))
}
