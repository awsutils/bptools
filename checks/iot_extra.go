package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTExtraChecks registers IoT Device Defender, IoT Events, and IoT Wireless checks.
func RegisterIoTExtraChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"iotdevicedefender-custom-metric-tagged",
		"AWS IoT Device Defender custom metrics have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iot",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			metrics, err := d.IoTCustomMetrics.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTCustomMetricTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range metrics {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotevents-alarm-model-tagged",
		"Checks if AWS IoT Events alarm models have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotevents",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			models, err := d.IoTEventsAlarmModels.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTEventsTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range models {
				id := "unknown"
				if m.AlarmModelName != nil {
					id = *m.AlarmModelName
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotevents-detector-model-tagged",
		"Checks if AWS IoT Events detector models have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotevents",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			models, err := d.IoTEventsDetectorModels.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTEventsTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range models {
				id := "unknown"
				if m.DetectorModelName != nil {
					id = *m.DetectorModelName
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotevents-input-tagged",
		"Checks if AWS IoT Events inputs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotevents",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			inputs, err := d.IoTEventsInputs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTEventsTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range inputs {
				id := "unknown"
				if m.InputArn != nil {
					id = *m.InputArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iotwireless-fuota-task-tagged",
		"Checks if AWS IoT Wireless FUOTA tasks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotwireless",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTWirelessFuotaTasks.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTWirelessTags.Get()
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
		"iotwireless-multicast-group-tagged",
		"Checks if AWS IoT Wireless multicast groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotwireless",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTWirelessMulticastGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTWirelessTags.Get()
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
		"iotwireless-service-profile-tagged",
		"Checks if AWS IoT Wireless service profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"iotwireless",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTWirelessServiceProfiles.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTWirelessTags.Get()
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
