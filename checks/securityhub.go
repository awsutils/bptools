package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterSecurityHubChecks registers Security Hub checks.
func RegisterSecurityHubChecks(d *awsdata.Data) {
	checker.Register(SingleCheck(
		"securityhub-enabled",
		"Checks if AWS Security Hub is enabled for an AWS Account. The rule is NON_COMPLIANT if AWS Security Hub is not enabled.",
		"securityhub",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			enabled, err := d.SecurityHubEnabled.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if enabled {
				return true, "Security Hub is enabled", nil
			}
			return false, "Security Hub is not enabled", nil
		},
	))
}
