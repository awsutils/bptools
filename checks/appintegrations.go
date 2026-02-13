package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

func RegisterAppIntegrationsChecks(d *awsdata.Data) {
	// appintegrations-event-integration-description
	checker.Register(DescriptionCheck(
		"appintegrations-event-integration-description",
		"Checks if Amazon AppIntegrations event integrations have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.",
		"appintegrations",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			events, err := d.AppIntegrationsEventIntegrations.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, e := range events {
				id := "unknown"
				if e.EventIntegrationArn != nil {
					id = *e.EventIntegrationArn
				}
				res = append(res, DescriptionResource{ID: id, Description: e.Description})
			}
			return res, nil
		},
	))

	// appintegrations-event-integration-tagged
	checker.Register(TaggedCheck(
		"appintegrations-event-integration-tagged",
		"Checks if Amazon AppIntegrations event integrations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appintegrations",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			events, err := d.AppIntegrationsEventIntegrations.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppIntegrationsTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, e := range events {
				if e.EventIntegrationArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *e.EventIntegrationArn, Tags: tags[*e.EventIntegrationArn]})
			}
			return res, nil
		},
	))
}
