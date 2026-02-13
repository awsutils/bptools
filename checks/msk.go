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
		"Checks if public access is disabled on Amazon MSK clusters. The rule is NON_COMPLIANT if public access on an Amazon MSK cluster is not disabled.",
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
		"Checks if Amazon MSK clusters have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon MSK Connector has logging enabled to any one of the log destinations. The rule is NON_COMPLIANT if Amazon MSK Connector does not have logging enabled.",
		"mskconnect",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			connectors, err := d.MSKConnectorDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for arn, c := range connectors {
				logging := false
				if c.LogDelivery != nil && c.LogDelivery.WorkerLogDelivery != nil {
					w := c.LogDelivery.WorkerLogDelivery
					logging = (w.CloudWatchLogs != nil && w.CloudWatchLogs.Enabled) ||
						(w.Firehose != nil && w.Firehose.Enabled) ||
						(w.S3 != nil && w.S3.Enabled)
				}
				res = append(res, LoggingResource{ID: arn, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"msk-enhanced-monitoring-enabled",
		"Checks if enhanced monitoring is enabled for an Amazon MSK cluster set to PER_TOPIC_PER_BROKER or PER_TOPIC_PER_PARTITION. The rule is NON_COMPLIANT if enhanced monitoring is enabled and set to DEFAULT or PER_BROKER.",
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
				enabled := c.Provisioned != nil && (c.Provisioned.EnhancedMonitoring == kafkatypes.EnhancedMonitoringPerTopicPerBroker ||
					c.Provisioned.EnhancedMonitoring == kafkatypes.EnhancedMonitoringPerTopicPerPartition)
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"msk-in-cluster-node-require-tls",
		"Checks if an Amazon MSK cluster enforces encryption in transit using HTTPS (TLS) with the broker nodes of the cluster. The rule is NON_COMPLIANT if plain text communication is enabled for in-cluster broker node connections.",
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
		"Checks if an Amazon MSK Cluster has unauthenticated access disabled. The rule is NON_COMPLIANT if Amazon MSK Cluster has unauthenticated access enabled.",
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
				if c.Provisioned != nil && c.Provisioned.ClientAuthentication != nil && c.Provisioned.ClientAuthentication.Unauthenticated != nil {
					ok = c.Provisioned.ClientAuthentication.Unauthenticated.Enabled == nil || !*c.Provisioned.ClientAuthentication.Unauthenticated.Enabled
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Unauthenticated client access disabled"})
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
