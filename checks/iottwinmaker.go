package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTTwinMakerChecks registers IoT TwinMaker checks.
func RegisterIoTTwinMakerChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"iottwinmaker-component-type-tagged",
		"This rule checks tagging for iottwinmaker component type exist.",
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
		"This rule checks tagging for iottwinmaker entity exist.",
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
		"This rule checks tagging for iottwinmaker scene exist.",
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
		"This rule checks tagging for iottwinmaker sync job exist.",
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
		"This rule checks tagging for iottwinmaker workspace exist.",
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
