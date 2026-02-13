package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIVSChecks registers IVS checks.
func RegisterIVSChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"ivs-channel-playback-authorization-enabled",
		"Checks if Amazon IVS channels have playback authorization enabled. The rule is NON_COMPLIANT if configuration.Authorized is false.",
		"ivs",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			channels, err := d.IVSChannelDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, ch := range channels {
				enabled := ch.Authorized
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"ivs-channel-tagged",
		"Checks if Amazon IVS channels have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"ivs",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			channels, err := d.IVSChannels.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IVSTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, ch := range channels {
				id := "unknown"
				if ch.Arn != nil {
					id = *ch.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"ivs-playback-key-pair-tagged",
		"Checks if Amazon IVS playback key pairs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"ivs",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			pairs, err := d.IVSPlaybackKeyPairs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IVSTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range pairs {
				id := "unknown"
				if p.Arn != nil {
					id = *p.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"ivs-recording-configuration-tagged",
		"Checks if Amazon IVS recording configurations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"ivs",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			rec, err := d.IVSRecordingConfigurations.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IVSTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, r := range rec {
				id := "unknown"
				if r.Arn != nil {
					id = *r.Arn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
