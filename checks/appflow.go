package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	appflowtypes "github.com/aws/aws-sdk-go-v2/service/appflow/types"
)

func RegisterAppFlowChecks(d *awsdata.Data) {
	// appflow-flow-tagged
	checker.Register(TaggedCheck(
		"appflow-flow-tagged",
		"This rule checks tagging for AppFlow flow exist.",
		"appflow",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			flows, err := d.AppFlowFlows.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppFlowTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, f := range flows {
				if f.FlowArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *f.FlowArn, Tags: tags[*f.FlowArn]})
			}
			return res, nil
		},
	))

	// appflow-flow-trigger-type-check
	checker.Register(ConfigCheck(
		"appflow-flow-trigger-type-check",
		"This rule checks configuration for AppFlow flow trigger type.",
		"appflow",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			details, err := d.AppFlowFlowDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, f := range details {
				trigger := appflowtypes.TriggerTypeOnDemand
				if f.TriggerConfig != nil {
					trigger = f.TriggerConfig.TriggerType
				}
				ok := trigger != appflowtypes.TriggerTypeOnDemand
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("TriggerType: %s", trigger)})
			}
			return res, nil
		},
	))
}
