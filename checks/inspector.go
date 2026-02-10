package checks

import (
	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// RegisterInspectorChecks registers Inspector checks.
func RegisterInspectorChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"inspector-ec2-scan-enabled",
		"This rule checks Inspector EC2 scan enabled.",
		"inspector",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			st, err := d.Inspector2Status.Get()
			if err != nil {
				return nil, err
			}
			enabled := inspector2ResourceEnabled(st, func(rs *inspector2types.ResourceState) *inspector2types.State {
				if rs == nil {
					return nil
				}
				return rs.Ec2
			})
			return []EnabledResource{{ID: "account", Enabled: enabled}}, nil
		},
	))

	checker.Register(EnabledCheck(
		"inspector-ecr-scan-enabled",
		"This rule checks Inspector ECR scan enabled.",
		"inspector",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			st, err := d.Inspector2Status.Get()
			if err != nil {
				return nil, err
			}
			enabled := inspector2ResourceEnabled(st, func(rs *inspector2types.ResourceState) *inspector2types.State {
				if rs == nil {
					return nil
				}
				return rs.Ecr
			})
			return []EnabledResource{{ID: "account", Enabled: enabled}}, nil
		},
	))

	checker.Register(EnabledCheck(
		"inspector-lambda-code-scan-enabled",
		"This rule checks Inspector Lambda code scan enabled.",
		"inspector",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			st, err := d.Inspector2Status.Get()
			if err != nil {
				return nil, err
			}
			enabled := inspector2ResourceEnabled(st, func(rs *inspector2types.ResourceState) *inspector2types.State {
				if rs == nil {
					return nil
				}
				return rs.LambdaCode
			})
			return []EnabledResource{{ID: "account", Enabled: enabled}}, nil
		},
	))

	checker.Register(EnabledCheck(
		"inspector-lambda-standard-scan-enabled",
		"This rule checks Inspector Lambda standard scan enabled.",
		"inspector",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			st, err := d.Inspector2Status.Get()
			if err != nil {
				return nil, err
			}
			enabled := inspector2ResourceEnabled(st, func(rs *inspector2types.ResourceState) *inspector2types.State {
				if rs == nil {
					return nil
				}
				return rs.Lambda
			})
			return []EnabledResource{{ID: "account", Enabled: enabled}}, nil
		},
	))
}

func inspector2ResourceEnabled(st inspector2.BatchGetAccountStatusOutput, selector func(*inspector2types.ResourceState) *inspector2types.State) bool {
	for _, acct := range st.Accounts {
		state := selector(acct.ResourceState)
		if state != nil && state.Status == inspector2types.StatusEnabled {
			return true
		}
	}
	return false
}
