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
		"Checks if Amazon Macie is enabled in your account per region. The rule is NON_COMPLIANT if the 'status' attribute is not set to 'ENABLED'.",
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
		"Checks if automated sensitive data discovery is enabled for Amazon Macie. The rule is NON_COMPLIANT if automated sensitive data discovery is disabled. The rule is APPLICABLE for administrator accounts and NOT_APPLICABLE for member accounts.",
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
