package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	sestypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// RegisterSESChecks registers SES checks.
func RegisterSESChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"ses-malware-scanning-enabled",
		"This rule checks enabled state for ses malware scanning.",
		"ses",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sets, err := d.SESReceiptRuleSets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, rules := range sets {
				ok := true
				for _, r := range rules {
					if !r.ScanEnabled {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{
					ID:      name,
					Passing: ok,
					Detail:  fmt.Sprintf("Rules with ScanEnabled=true: %d/%d", countScanEnabled(rules), len(rules)),
				})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ses-sending-tls-required",
		"This rule checks ses sending tls required.",
		"ses",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			sets, err := d.SESv2ConfigurationSets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, cfg := range sets {
				tlsPolicy := sesv2types.TlsPolicyOptional
				if cfg.DeliveryOptions != nil {
					tlsPolicy = cfg.DeliveryOptions.TlsPolicy
				}
				ok := tlsPolicy == sesv2types.TlsPolicyRequire
				res = append(res, ConfigResource{
					ID:      name,
					Passing: ok,
					Detail:  fmt.Sprintf("TlsPolicy: %s", tlsPolicy),
				})
			}
			return res, nil
		},
	))
}

func countScanEnabled(rules []sestypes.ReceiptRule) int {
	count := 0
	for _, r := range rules {
		if r.ScanEnabled {
			count++
		}
	}
	return count
}
