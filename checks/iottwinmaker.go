package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTTwinMakerChecks registers IoT TwinMaker checks.
func RegisterIoTTwinMakerChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"iottwinmaker-component-type-tagged",
		"Checks if AWS IoT TwinMaker component types have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iottwinmaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.TwinMakerComponentTypes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TwinMakerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, list := range items {
				for _, it := range list {
					id := "unknown"
					if it.Arn != nil {
						id = *it.Arn
					}
					res = append(res, TaggedResource{ID: id, Tags: tags[id]})
				}
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iottwinmaker-entity-tagged",
		"Checks if AWS IoT TwinMaker entities have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iottwinmaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.TwinMakerEntities.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TwinMakerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, list := range items {
				for _, it := range list {
					id := "unknown"
					if it.Arn != nil {
						id = *it.Arn
					}
					res = append(res, TaggedResource{ID: id, Tags: tags[id]})
				}
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iottwinmaker-scene-tagged",
		"Checks if AWS IoT TwinMaker scenes have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iottwinmaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.TwinMakerScenes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TwinMakerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, list := range items {
				for _, it := range list {
					id := "unknown"
					if it.Arn != nil {
						id = *it.Arn
					}
					res = append(res, TaggedResource{ID: id, Tags: tags[id]})
				}
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iottwinmaker-sync-job-tagged",
		"Checks if AWS IoT TwinMaker sync jobs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iottwinmaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.TwinMakerSyncJobs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TwinMakerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, list := range items {
				for _, it := range list {
					id := "unknown"
					if it.Arn != nil {
						id = *it.Arn
					}
					res = append(res, TaggedResource{ID: id, Tags: tags[id]})
				}
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iottwinmaker-workspace-tagged",
		"Checks if AWS IoT TwinMaker workspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iottwinmaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.TwinMakerWorkspaces.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TwinMakerTags.Get()
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
