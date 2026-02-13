package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTSiteWiseChecks registers IoT SiteWise checks.
func RegisterIoTSiteWiseChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"iotsitewise-asset-model-tagged",
		"Checks if AWS IoT SiteWise asset models have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotsitewise",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTSiteWiseAssetModels.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTSiteWiseTags.Get()
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
		"iotsitewise-dashboard-tagged",
		"Checks if AWS IoT SiteWise dashboards have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotsitewise",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTSiteWiseDashboards.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTSiteWiseTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Id != nil {
					id = *it.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotsitewise-gateway-tagged",
		"Checks if AWS IoT SiteWise gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotsitewise",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTSiteWiseGateways.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTSiteWiseTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.GatewayId != nil {
					id = *it.GatewayId
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotsitewise-portal-tagged",
		"Checks if AWS IoT SiteWise portals have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotsitewise",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTSiteWisePortals.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTSiteWiseTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Id != nil {
					id = *it.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotsitewise-project-tagged",
		"Checks if AWS IoT SiteWise projects have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotsitewise",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTSiteWiseProjects.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTSiteWiseTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.Id != nil {
					id = *it.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
