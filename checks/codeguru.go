package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCodeGuruChecks registers CodeGuru checks.
func RegisterCodeGuruChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"codeguruprofiler-profiling-group-tagged",
		"Checks if Amazon CodeGuru Profiler profiling groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon CodeGuru Reviewer repository associations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
