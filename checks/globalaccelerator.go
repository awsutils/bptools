package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterGlobalAcceleratorChecks registers Global Accelerator checks.
func RegisterGlobalAcceleratorChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"glb-tagged",
		"This rule checks glb tagged.",
		"globalaccelerator",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			accels, err := d.GlobalAccelerators.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.GlobalAcceleratorTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range accels {
				id := "unknown"
				if a.AcceleratorArn != nil {
					id = *a.AcceleratorArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"glb-listener-tagged",
		"This rule checks glb listener tagged.",
		"globalaccelerator",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			listeners, err := d.GlobalAcceleratorListeners.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.GlobalAcceleratorListenerTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, ls := range listeners {
				for _, l := range ls {
					id := "unknown"
					if l.ListenerArn != nil {
						id = *l.ListenerArn
					}
					res = append(res, TaggedResource{ID: id, Tags: tags[id]})
				}
			}
			return res, nil
		},
	))
}
