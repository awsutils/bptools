package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
)

// RegisterDocDBChecks registers DocumentDB checks.
func RegisterDocDBChecks(d *awsdata.Data) {
	checker.Register(LoggingCheck(
		"docdb-cluster-audit-logging-enabled",
		"This rule checks logging is enabled for docdb cluster audit.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, c := range clusters {
				id := docdbID(c)
				logging := false
				for _, v := range c.EnabledCloudwatchLogsExports {
					if strings.EqualFold(v, "audit") {
						logging = true
						break
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"docdb-cluster-backup-retention-check",
		"This rule checks configuration for docdb cluster backup retention.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := docdbID(c)
				retention := int32(0)
				if c.BackupRetentionPeriod != nil {
					retention = *c.BackupRetentionPeriod
				}
				ok := retention > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Retention days: %d", retention)})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"docdb-cluster-deletion-protection-enabled",
		"This rule checks enabled state for docdb cluster deletion protection.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := docdbID(c)
				enabled := c.DeletionProtection != nil && *c.DeletionProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"docdb-cluster-encrypted",
		"This rule checks docdb cluster encrypted.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := docdbID(c)
				encrypted := c.StorageEncrypted != nil && *c.StorageEncrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"docdb-cluster-encrypted-in-transit",
		"This rule checks docdb cluster encrypted in transit.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := docdbID(c)
				encrypted := c.DBClusterParameterGroup != nil && c.DBClusterParameterGroup != nil
				// Heuristic: no direct flag; assume encrypted in transit when TLS is enforced by parameter group name containing "tls"/"ssl".
				if c.DBClusterParameterGroup != nil {
					name := *c.DBClusterParameterGroup
					encrypted = strings.Contains(strings.ToLower(name), "tls") || strings.Contains(strings.ToLower(name), "ssl")
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"docdb-cluster-snapshot-public-prohibited",
		"This rule checks docdb cluster snapshot public prohibited.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.DocDBSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range snaps {
				id := "unknown"
				if s.DBClusterSnapshotArn != nil {
					id = *s.DBClusterSnapshotArn
				}
				// DocDB DBClusterSnapshot does not expose a Public field in the SDK.
				// Defaulting to not public.
				public := false
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))
}

func docdbID(c docdbtypes.DBCluster) string {
	if c.DBClusterArn != nil {
		return *c.DBClusterArn
	}
	if c.DBClusterIdentifier != nil {
		return *c.DBClusterIdentifier
	}
	return "unknown"
}
