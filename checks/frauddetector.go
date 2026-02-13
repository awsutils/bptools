package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterFraudDetectorChecks registers Fraud Detector checks.
func RegisterFraudDetectorChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"frauddetector-entity-type-tagged",
		"Checks if Amazon Fraud Detector entity types have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Fraud Detector labels have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Fraud Detector outcomes have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Fraud Detector variables have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
