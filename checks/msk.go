package checks

import (
	"bptools/awsdata"
	"bptools/checker"

	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
)

// RegisterMSKChecks registers MSK checks.
func RegisterMSKChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"msk-cluster-public-access-disabled",
		"This rule checks disabled state for msk cluster public access.",
		"msk",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.MSKClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := mskID(c)
				enabled := true
				if c.Provisioned != nil && c.Provisioned.BrokerNodeGroupInfo != nil && c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo != nil && c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess != nil {
					enabled = c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type != nil &&
						*c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type == "DISABLED"
				}
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"msk-cluster-tagged",
		"This rule checks tagging for msk cluster exist.",
		"msk",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			clusters, err := d.MSKClusters.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.MSKClusterTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, c := range clusters {
				id := mskID(c)
				key := ""
				if c.ClusterArn != nil {
					key = *c.ClusterArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[key]})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"msk-connect-connector-logging-enabled",
		"This rule checks logging is enabled for msk connect connector.",
		"mskconnect",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			connectors, err := d.MSKConnectorDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for arn, c := range connectors {
				logging := c.LogDelivery != nil
				res = append(res, LoggingResource{ID: arn, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"msk-enhanced-monitoring-enabled",
		"This rule checks enabled state for msk enhanced monitoring.",
		"msk",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.MSKClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := mskID(c)
				enabled := c.Provisioned != nil && c.Provisioned.EnhancedMonitoring != kafkatypes.EnhancedMonitoringDefault
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"msk-in-cluster-node-require-tls",
		"This rule checks msk in cluster node require TLS.",
		"msk",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.MSKClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := mskID(c)
				ok := c.Provisioned != nil &&
					c.Provisioned.EncryptionInfo != nil &&
					c.Provisioned.EncryptionInfo.EncryptionInTransit != nil &&
					c.Provisioned.EncryptionInfo.EncryptionInTransit.InCluster != nil &&
					*c.Provisioned.EncryptionInfo.EncryptionInTransit.InCluster
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "InCluster TLS"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"msk-unrestricted-access-check",
		"This rule checks configuration for msk unrestricted access.",
		"msk",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.MSKClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := mskID(c)
				ok := true
				if c.Provisioned != nil && c.Provisioned.BrokerNodeGroupInfo != nil && c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo != nil && c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess != nil {
					ok = c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type != nil &&
						*c.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type == "DISABLED"
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Public access disabled"})
			}
			return res, nil
		},
	))
}

func mskID(c kafkatypes.Cluster) string {
	if c.ClusterArn != nil {
		return *c.ClusterArn
	}
	if c.ClusterName != nil {
		return *c.ClusterName
	}
	return "unknown"
}
