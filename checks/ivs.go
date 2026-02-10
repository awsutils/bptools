package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIVSChecks registers IVS checks.
func RegisterIVSChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"ivs-channel-playback-authorization-enabled",
		"This rule checks IVS channel playback authorization enabled.",
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
		"This rule checks tagging for IVS channel exist.",
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
		"This rule checks tagging for IVS playback key pair exist.",
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
		"This rule checks tagging for IVS recording configuration exist.",
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
