package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterSecurityHubChecks registers Security Hub checks.
func RegisterSecurityHubChecks(d *awsdata.Data) {
	checker.Register(SingleCheck(
		"securityhub-enabled",
		"This rule checks enabled state for securityhub.",
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
