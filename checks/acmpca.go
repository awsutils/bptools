package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

// RegisterACMPcaChecks registers ACM PCA-related checks.
func RegisterACMPcaChecks(d *awsdata.Data) {
	// acmpca-certificate-authority-tagged
	checker.Register(TaggedCheck(
		"acmpca-certificate-authority-tagged",
		"Checks if AWS Private CA certificate authorities have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"acmpca",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			cas, err := d.ACMPCACertificateAuthorities.Get()
			if err != nil {
				return nil, err
			}
			tagsByArn, err := d.ACMPCACertificateAuthorityTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, ca := range cas {
				if ca.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *ca.Arn, Tags: tagsByArn[*ca.Arn]})
			}
			return res, nil
		},
	))

	// acm-pca-root-ca-disabled
	checker.Register(ConfigCheck(
		"acm-pca-root-ca-disabled",
		"Checks if AWS Private Certificate Authority (AWS Private CA) has a root CA that is disabled. The rule is NON_COMPLIANT for root CAs with status that is not DISABLED.",
		"acmpca",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			cas, err := d.ACMPCACertificateAuthorities.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ca := range cas {
				if ca.Arn == nil {
					continue
				}
				if ca.Type != acmpcatypes.CertificateAuthorityTypeRoot {
					res = append(res, ConfigResource{ID: *ca.Arn, Passing: true, Detail: "Not a root CA"})
					continue
				}
				disabled := ca.Status == acmpcatypes.CertificateAuthorityStatusDisabled
				res = append(res, ConfigResource{ID: *ca.Arn, Passing: disabled, Detail: fmt.Sprintf("Status: %s", ca.Status)})
			}
			return res, nil
		},
	))
}
