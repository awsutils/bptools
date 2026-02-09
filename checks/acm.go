package checks

import (
	"fmt"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"
)

const acmExpirationThreshold = 90 * 24 * time.Hour

func certID(arn *string) string {
	if arn != nil {
		return *arn
	}
	return "unknown"
}

// RegisterACMChecks registers ACM-related checks.
func RegisterACMChecks(d *awsdata.Data) {
	// acm-certificate-expiration-check
	checker.Register(ConfigCheck(
		"acm-certificate-expiration-check",
		"This rule checks expiration for ACM certificate.",
		"acm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			certs, err := d.ACMCertificateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, c := range certs {
				if c.NotAfter == nil {
					res = append(res, ConfigResource{ID: arn, Passing: false, Detail: "Missing expiration date"})
					continue
				}
				remaining := time.Until(*c.NotAfter)
				ok := remaining >= acmExpirationThreshold
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Expires in %s", remaining.Truncate(time.Hour))})
			}
			return res, nil
		},
	))

	// acm-certificate-rsa-check
	checker.Register(ConfigCheck(
		"acm-certificate-rsa-check",
		"This rule checks RSA usage for ACM certificate.",
		"acm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			certs, err := d.ACMCertificateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, c := range certs {
				alg := string(c.KeyAlgorithm)
				ok := strings.HasPrefix(alg, "RSA")
				if alg == "" {
					ok = false
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Key algorithm: %s", alg)})
			}
			return res, nil
		},
	))
}
