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
		"Checks if Amazon Inspector V2 EC2 scanning is activated for your single or multi-account environment to detect potential vulnerabilities and network reachability issues on your EC2 instances. The rule is NON_COMPLIANT if EC2 scanning is not activated.",
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
		"Checks if Amazon Inspector V2 ECR scanning is activated for your single or multi-account environment to detect potential software vulnerabilities in your container images. The rule is NON_COMPLIANT if ECR scanning is not activated.",
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
		"Checks if Amazon Inspector V2 Lambda code scanning is activated for your single or multi-account environment to detect potential code vulnerabilities. The rule is NON_COMPLIANT if Lambda code scanning is not activated.",
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
		"Checks if Amazon Inspector V2 Lambda standard scanning is activated for your single or multi-account environment to detect potential software vulnerabilities. The rule is NON_COMPLIANT if Lambda standard scanning is not activated.",
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
