package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterFraudDetectorChecks registers Fraud Detector checks.
func RegisterFraudDetectorChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"frauddetector-entity-type-tagged",
		"This rule checks tagging for frauddetector entity type exist.",
		"frauddetector",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.FraudDetectorEntityTypes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.FraudDetectorEntityTypeTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Arn != nil {
					id = *it.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"frauddetector-label-tagged",
		"This rule checks tagging for frauddetector label exist.",
		"frauddetector",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.FraudDetectorLabels.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.FraudDetectorLabelTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Arn != nil {
					id = *it.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"frauddetector-outcome-tagged",
		"This rule checks tagging for frauddetector outcome exist.",
		"frauddetector",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.FraudDetectorOutcomes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.FraudDetectorOutcomeTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Arn != nil {
					id = *it.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"frauddetector-variable-tagged",
		"This rule checks tagging for frauddetector variable exist.",
		"frauddetector",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.FraudDetectorVariables.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.FraudDetectorVariableTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Arn != nil {
					id = *it.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
