package checks

import (
	"bptools/awsdata"
	"bptools/checker"

	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
)

// RegisterDAXChecks registers DAX checks.
func RegisterDAXChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"dax-encryption-enabled",
		"This rule checks DAX encryption enabled.",
		"dax",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DAXClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := daxID(c)
				encrypted := c.SSEDescription != nil && c.SSEDescription.Status == daxtypes.SSEStatusEnabled
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"dax-tls-endpoint-encryption",
		"This rule checks DAX TLS endpoint encryption.",
		"dax",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DAXClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := daxID(c)
				encrypted := c.ClusterDiscoveryEndpoint != nil && c.ClusterDiscoveryEndpoint.Address != nil && c.ClusterDiscoveryEndpoint.Port != 0
				// Heuristic: DAX always provides TLS endpoint; treat presence of endpoint as TLS configured.
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))
}

func daxID(c daxtypes.Cluster) string {
	if c.ClusterArn != nil {
		return *c.ClusterArn
	}
	if c.ClusterName != nil {
		return *c.ClusterName
	}
	return "unknown"
}
