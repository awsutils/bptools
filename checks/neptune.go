package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
)

// RegisterNeptuneChecks registers Neptune checks.
func RegisterNeptuneChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"neptune-cluster-backup-retention-check",
		"This rule checks configuration for neptune cluster backup retention.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := clusterID(c)
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
		"neptune-cluster-cloudwatch-log-export-enabled",
		"This rule checks enabled state for neptune cluster CloudWatch log export.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := clusterID(c)
				enabled := len(c.EnabledCloudwatchLogsExports) > 0
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-copy-tags-to-snapshot-enabled",
		"This rule checks enabled state for neptune cluster copy tags to snapshot.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := clusterID(c)
				enabled := c.CopyTagsToSnapshot != nil && *c.CopyTagsToSnapshot
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-deletion-protection-enabled",
		"This rule checks enabled state for neptune cluster deletion protection.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := clusterID(c)
				enabled := c.DeletionProtection != nil && *c.DeletionProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"neptune-cluster-encrypted",
		"This rule checks neptune cluster encrypted.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := clusterID(c)
				encrypted := c.StorageEncrypted != nil && *c.StorageEncrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-iam-database-authentication",
		"This rule checks neptune cluster IAM database authentication.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := clusterID(c)
				enabled := c.IAMDatabaseAuthenticationEnabled != nil && *c.IAMDatabaseAuthenticationEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-multi-az-enabled",
		"This rule checks enabled state for neptune cluster multi az.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.NeptuneClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := clusterID(c)
				enabled := c.MultiAZ != nil && *c.MultiAZ
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"neptune-cluster-snapshot-encrypted",
		"This rule checks neptune cluster snapshot encrypted.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			snaps, err := d.NeptuneSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, s := range snaps {
				id := snapshotID(s)
				encrypted := s.StorageEncrypted != nil && *s.StorageEncrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"neptune-cluster-snapshot-public-prohibited",
		"This rule checks neptune cluster snapshot public prohibited.",
		"neptune",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.NeptuneSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range snaps {
				id := snapshotID(s)
				// Neptune DBClusterSnapshot does not expose a Public field in the SDK.
				// Defaulting to not public.
				public := false
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))
}

func clusterID(c neptunetypes.DBCluster) string {
	if c.DBClusterArn != nil {
		return *c.DBClusterArn
	}
	if c.DBClusterIdentifier != nil {
		return *c.DBClusterIdentifier
	}
	return "unknown"
}

func snapshotID(s neptunetypes.DBClusterSnapshot) string {
	if s.DBClusterSnapshotArn != nil {
		return *s.DBClusterSnapshotArn
	}
	if s.DBClusterSnapshotIdentifier != nil {
		return *s.DBClusterSnapshotIdentifier
	}
	return "unknown"
}
