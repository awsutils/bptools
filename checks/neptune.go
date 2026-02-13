package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
)

// RegisterNeptuneChecks registers Neptune checks.
func RegisterNeptuneChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"neptune-cluster-backup-retention-check",
		"Checks if an Amazon Neptune DB cluster retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period is less than the value specified by the parameter.",
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
				ok := retention >= 7
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Retention days: %d", retention)})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-cloudwatch-log-export-enabled",
		"Checks if an Amazon Neptune cluster has CloudWatch log export enabled for audit logs. The rule is NON_COMPLIANT if a Neptune cluster does not have CloudWatch log export enabled for audit logs.",
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
				enabled := false
				for _, logType := range c.EnabledCloudwatchLogsExports {
					if strings.EqualFold(logType, "audit") {
						enabled = true
						break
					}
				}
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"neptune-cluster-copy-tags-to-snapshot-enabled",
		"Checks if an Amazon Neptune cluster is configured to copy all tags to snapshots when the snapshots are created. The rule is NON_COMPLIANT if 'copyTagsToSnapshot' is set to false.",
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
		"Checks if an Amazon Neptune DB cluster has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon Neptune cluster has the deletionProtection field set to false.",
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
		"Checks if storage encryption is enabled for your Amazon Neptune DB clusters. The rule is NON_COMPLIANT if storage encryption is not enabled.",
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
		"Checks if an Amazon Neptune cluster has AWS Identity and Access Management (IAM) database authentication enabled. The rule is NON_COMPLIANT if an Amazon Neptune cluster does not have IAM database authentication enabled.",
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
		"Checks if an Amazon Neptune cluster is configured with Amazon RDS Multi-AZ replication. The rule is NON_COMPLIANT if Multi-AZ replication is not enabled.",
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
		"Checks if an Amazon Neptune DB cluster has snapshots encrypted. The rule is NON_COMPLIANT if a Neptune cluster does not have snapshots encrypted.",
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
		"Checks if an Amazon Neptune manual DB cluster snapshot is public. The rule is NON_COMPLIANT if any existing and new Neptune cluster snapshot is public.",
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
				if s.DBClusterSnapshotIdentifier == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing DBClusterSnapshotIdentifier"})
					continue
				}
				out, err := d.Clients.Neptune.DescribeDBClusterSnapshotAttributes(d.Ctx, &neptune.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: s.DBClusterSnapshotIdentifier})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("DescribeDBClusterSnapshotAttributes failed: %v", err)})
					continue
				}
				public := snapshotAttributesIncludePublic(out.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes)
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public restore access: %v", public)})
			}
			return res, nil
		},
	))
}

func snapshotAttributesIncludePublic(attrs []neptunetypes.DBClusterSnapshotAttribute) bool {
	for _, attr := range attrs {
		if attr.AttributeName == nil || !strings.EqualFold(*attr.AttributeName, "restore") {
			continue
		}
		for _, v := range attr.AttributeValues {
			if strings.EqualFold(v, "all") {
				return true
			}
		}
	}
	return false
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
