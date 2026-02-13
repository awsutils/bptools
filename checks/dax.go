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
		"Checks if Amazon DynamoDB Accelerator (DAX) clusters are encrypted. The rule is NON_COMPLIANT if a DAX cluster is not encrypted.",
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
		"Checks if your Amazon DynamoDB Accelerator (DAX) cluster has ClusterEndpointEncryptionType set to TLS. The rule is NON_COMPLIANT if a DAX cluster is not encrypted by transport layer security (TLS).",
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
				encrypted := c.ClusterEndpointEncryptionType == daxtypes.ClusterEndpointEncryptionTypeTls
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
