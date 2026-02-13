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
		"Checks if the actual configuration of a AWS CloudFormation (CloudFormation) stack differs, or has drifted, from the expected configuration. A stack is considered to have drifted if one or more of its resources differ from their expected configuration. The rule and the stack are COMPLIANT when the stack drift status is IN_SYNC. The rule is NON_COMPLIANT if the stack drift status is DRIFTED.",
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
		"Checks if your CloudFormation stacks send event notifications to an Amazon SNS topic. Optionally checks if specified Amazon SNS topics are used. The rule is NON_COMPLIANT if CloudFormation stacks do not send notifications.",
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
		"Checks if AWS CloudFormation stacks are using service roles. The rule is NON_COMPLIANT if a CloudFormation stack does not have service role associated with it.",
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
		"Checks if an AWS CloudFormation stack has termination protection enabled. This rule is NON_COMPLIANT if termination protection is not enabled on a CloudFormation stack.",
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
