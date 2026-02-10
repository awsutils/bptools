package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterAMPChecks registers AMP (Prometheus) checks.
func RegisterAMPChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"aps-rule-groups-namespace-tagged",
		"This rule checks aps rule groups namespace tagged.",
		"amp",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			namespaces, err := d.AMPRuleGroupsNamespaces.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, ns := range namespaces {
				id := "unknown"
				if ns.Arn != nil {
					id = *ns.Arn
				} else if ns.Name != nil {
					id = *ns.Name
				}
				res = append(res, TaggedResource{ID: id, Tags: ns.Tags})
			}
			return res, nil
		},
	))
}
