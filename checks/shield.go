package checks

import (
	"bptools/awsdata"
	"bptools/checker"

	shieldtypes "github.com/aws/aws-sdk-go-v2/service/shield/types"
)

// RegisterShieldChecks registers Shield checks.
func RegisterShieldChecks(d *awsdata.Data) {
	checker.Register(SingleCheck(
		"shield-advanced-enabled-autorenew",
		"This rule checks shield advanced enabled autorenew.",
		"shield",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			sub, err := d.ShieldSubscription.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if sub.Subscription == nil {
				return false, "Shield Advanced subscription not found", nil
			}
			if sub.Subscription.AutoRenew == shieldtypes.AutoRenewEnabled {
				return true, "Shield Advanced auto-renew enabled", nil
			}
			return false, "Shield Advanced auto-renew disabled", nil
		},
	))

	checker.Register(SingleCheck(
		"shield-drt-access",
		"This rule checks shield drt access.",
		"shield",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			access, err := d.ShieldDRTAccess.Get()
			if err != nil {
				return false, err.Error(), err
			}
			ok := access.RoleArn != nil && *access.RoleArn != ""
			if ok {
				return true, "DRT access role configured", nil
			}
			return false, "DRT access role not configured", nil
		},
	))
}
