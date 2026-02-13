package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"
)

const acmDefaultExpirationDays = 90

func acmExpirationThreshold() time.Duration {
	if v := strings.TrimSpace(os.Getenv("BPTOOLS_ACM_EXPIRATION_DAYS")); v != "" {
		if days, err := strconv.Atoi(v); err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	return acmDefaultExpirationDays * 24 * time.Hour
}

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
		"Checks if AWS Certificate Manager Certificates in your account are marked for expiration within the specified number of days. Certificates provided by ACM are automatically renewed. ACM does not automatically renew certificates that you import. The rule is NON_COMPLIANT if your certificates are about to expire.",
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
				ok := remaining >= acmExpirationThreshold()
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: fmt.Sprintf("Expires in %s", remaining.Truncate(time.Hour))})
			}
			return res, nil
		},
	))

	// acm-certificate-rsa-check
	checker.Register(ConfigCheck(
		"acm-certificate-rsa-check",
		"Checks if RSA certificates managed by AWS Certificate Manager (ACM) have a key length of at least '2048' bits.The rule is NON_COMPLIANT if the minimum key length is less than 2048 bits.",
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
				ok := true
				detail := fmt.Sprintf("Key algorithm: %s", alg)
				if strings.HasPrefix(alg, "RSA_") {
					bits, parseErr := rsaKeySizeBits(alg)
					ok = parseErr == nil && bits >= 2048
					if parseErr != nil {
						detail = fmt.Sprintf("Unable to parse RSA key size from %s", alg)
					} else {
						detail = fmt.Sprintf("RSA key size: %d", bits)
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
}

func rsaKeySizeBits(algorithm string) (int, error) {
	parts := strings.SplitN(algorithm, "_", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid RSA key algorithm format")
	}
	return strconv.Atoi(parts[1])
}
