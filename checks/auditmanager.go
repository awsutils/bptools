package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterAuditManagerChecks registers Audit Manager checks.
func RegisterAuditManagerChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"auditmanager-assessment-tagged",
		"This rule checks auditmanager assessment tagged.",
		"auditmanager",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			assessments, err := d.AuditManagerAssessments.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for id, a := range assessments {
				resID := id
				if a.Arn != nil {
					resID = *a.Arn
				}
				res = append(res, TaggedResource{ID: resID, Tags: a.Tags})
			}
			return res, nil
		},
	))
}
