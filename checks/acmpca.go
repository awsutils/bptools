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
		"This rule checks tagging for ACM PCA certificate authority exist.",
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
		"This rule checks disabled state for ACM PCA root CA.",
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
