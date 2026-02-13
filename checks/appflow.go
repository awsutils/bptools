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
		"Checks if Amazon AppFlow flows have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if an Amazon AppFlow flow runs using the specified trigger type. The rule is NON_COMPLAINT if the flow does not run using the flow type specified in the required rule parameter.",
		"appflow",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			details, err := d.AppFlowFlowDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, f := range details {
				trigger := appflowtypes.TriggerTypeOndemand
				if f.TriggerConfig != nil {
					trigger = f.TriggerConfig.TriggerType
				}
				ok := trigger != appflowtypes.TriggerTypeOndemand
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("TriggerType: %s", trigger)})
			}
			return res, nil
		},
	))
}
