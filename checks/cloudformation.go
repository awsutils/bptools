package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// RegisterCloudFormationChecks registers CloudFormation checks.
func RegisterCloudFormationChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"cloudformation-stack-drift-detection-check",
		"This rule checks cloudformation stack drift detection check.",
		"cloudformation",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stacks, err := d.CloudFormationStackDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, st := range stacks {
				id := stackID(st)
				var status cftypes.StackDriftStatus
				if st.DriftInformation != nil {
					status = st.DriftInformation.StackDriftStatus
				}
				ok := st.DriftInformation != nil && st.DriftInformation.StackDriftStatus == cftypes.StackDriftStatusInSync
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("StackDriftStatus: %s", status)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudformation-stack-notification-check",
		"This rule checks cloudformation stack notification check.",
		"cloudformation",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stacks, err := d.CloudFormationStackDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, st := range stacks {
				id := stackID(st)
				ok := len(st.NotificationARNs) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("NotificationARNs: %d", len(st.NotificationARNs))})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudformation-stack-service-role-check",
		"This rule checks cloudformation stack service role check.",
		"cloudformation",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stacks, err := d.CloudFormationStackDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, st := range stacks {
				id := stackID(st)
				ok := st.RoleARN != nil && *st.RoleARN != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Service role configured"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloudformation-termination-protection-check",
		"This rule checks cloudformation termination protection check.",
		"cloudformation",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			stacks, err := d.CloudFormationStackDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, st := range stacks {
				id := stackID(st)
				enabled := st.EnableTerminationProtection != nil && *st.EnableTerminationProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
}

func stackID(st cftypes.Stack) string {
	if st.StackId != nil {
		return *st.StackId
	}
	if st.StackName != nil {
		return *st.StackName
	}
	return "unknown"
}
