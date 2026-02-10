package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	macie2types "github.com/aws/aws-sdk-go-v2/service/macie2/types"
)

// RegisterMacieChecks registers Macie checks.
func RegisterMacieChecks(d *awsdata.Data) {
	checker.Register(SingleCheck(
		"macie-status-check",
		"This rule checks macie status check.",
		"macie2",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			sess, err := d.MacieSession.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if sess == nil {
				return false, "Macie session not found", nil
			}
			ok := sess.Status == macie2types.MacieStatusEnabled
			return ok, fmt.Sprintf("Status: %s", sess.Status), nil
		},
	))

	checker.Register(SingleCheck(
		"macie-auto-sensitive-data-discovery-check",
		"This rule checks macie auto sensitive data discovery check.",
		"macie2",
		d,
		func(d *awsdata.Data) (bool, string, error) {
			cfg, err := d.MacieAutomatedDiscoveryConfig.Get()
			if err != nil {
				return false, err.Error(), err
			}
			if cfg == nil {
				return false, "Automated discovery config not found", nil
			}
			enabled := cfg.DisabledAt == nil
			return enabled, fmt.Sprintf("DisabledAt: %v", cfg.DisabledAt), nil
		},
	))
}
