package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

var rdsDefaultAdmins = map[string]bool{"admin": true, "root": true, "master": true, "rdsadmin": true, "postgres": true}

func RegisterRDSChecks(d *awsdata.Data) {
	// rds-storage-encrypted
	checker.Register(EncryptionCheck(
		"rds-storage-encrypted",
		"This rule checks RDS storage encrypted.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: inst.StorageEncrypted != nil && *inst.StorageEncrypted})
			}
			return res, nil
		},
	))

	// rds-cluster-encrypted-at-rest
	checker.Register(EncryptionCheck(
		"rds-cluster-encrypted-at-rest",
		"This rule checks RDS cluster encrypted at rest.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: c.StorageEncrypted != nil && *c.StorageEncrypted})
			}
			return res, nil
		},
	))

	// rds-instance-public-access-check
	checker.Register(ConfigCheck(
		"rds-instance-public-access-check",
		"This rule checks RDS instance public access.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				public := inst.PubliclyAccessible != nil && *inst.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))

	// rds-instance-deletion-protection-enabled + rds-cluster-deletion-protection-enabled
	checker.Register(EnabledCheck(
		"rds-instance-deletion-protection-enabled",
		"This rule checks RDS instance deletion protection enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				enabled := inst.DeletionProtection != nil && *inst.DeletionProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(EnabledCheck(
		"rds-cluster-deletion-protection-enabled",
		"This rule checks RDS cluster deletion protection enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				enabled := c.DeletionProtection != nil && *c.DeletionProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-instance-iam-authentication-enabled + rds-cluster-iam-authentication-enabled
	checker.Register(EnabledCheck(
		"rds-instance-iam-authentication-enabled",
		"This rule checks RDS instance IAM authentication enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				enabled := inst.IAMDatabaseAuthenticationEnabled != nil && *inst.IAMDatabaseAuthenticationEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(EnabledCheck(
		"rds-cluster-iam-authentication-enabled",
		"This rule checks RDS cluster IAM authentication enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				enabled := c.IAMDatabaseAuthenticationEnabled != nil && *c.IAMDatabaseAuthenticationEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-automatic-minor-version-upgrade-enabled
	checker.Register(EnabledCheck(
		"rds-automatic-minor-version-upgrade-enabled",
		"This rule checks RDS automatic minor version upgrade.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				enabled := inst.AutoMinorVersionUpgrade != nil && *inst.AutoMinorVersionUpgrade
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-cluster-auto-minor-version-upgrade-enable
	checker.Register(EnabledCheck(
		"rds-cluster-auto-minor-version-upgrade-enable",
		"This rule checks RDS cluster auto minor version upgrade.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				enabled := c.AutoMinorVersionUpgrade != nil && *c.AutoMinorVersionUpgrade
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-enhanced-monitoring-enabled
	checker.Register(EnabledCheck(
		"rds-enhanced-monitoring-enabled",
		"This rule checks RDS enhanced monitoring enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				enabled := inst.MonitoringInterval != nil && *inst.MonitoringInterval > 0
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-event-subscription-tagged
	checker.Register(TaggedCheck(
		"rds-event-subscription-tagged",
		"This rule checks RDS event subscription tagged.",
		"rds",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			subs, err := d.RDSEventSubs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.RDSEventSubTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, s := range subs {
				if s.EventSubscriptionArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *s.EventSubscriptionArn, Tags: tags[*s.EventSubscriptionArn]})
			}
			return res, nil
		},
	))

	// rds-option-group-tagged
	checker.Register(TaggedCheck(
		"rds-option-group-tagged",
		"This rule checks RDS option group tagged.",
		"rds",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			groups, err := d.RDSOptionGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.RDSOptionGroupTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, g := range groups {
				if g.OptionGroupArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *g.OptionGroupArn, Tags: tags[*g.OptionGroupArn]})
			}
			return res, nil
		},
	))

	// rds-instance-default-admin-check + rds-cluster-default-admin-check
	checker.Register(ConfigCheck(
		"rds-instance-default-admin-check",
		"This rule checks RDS instance default admin.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				user := ""
				if inst.MasterUsername != nil {
					user = strings.ToLower(*inst.MasterUsername)
				}
				ok := !rdsDefaultAdmins[user]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("MasterUsername: %s", user)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-cluster-default-admin-check",
		"This rule checks RDS cluster default admin.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				user := ""
				if c.MasterUsername != nil {
					user = strings.ToLower(*c.MasterUsername)
				}
				ok := !rdsDefaultAdmins[user]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("MasterUsername: %s", user)})
			}
			return res, nil
		},
	))

	// rds-logging-enabled + engine-specific logging checks
	checker.Register(LoggingCheck(
		"rds-logging-enabled",
		"This rule checks RDS logging enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				logging := len(inst.EnabledCloudwatchLogsExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(LoggingCheck("rds-aurora-mysql-audit-logging-enabled", "This rule checks Aurora MySQL audit logging enabled.", "rds", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-mysql") {
					continue
				}
				id := *c.DBClusterIdentifier
				logging := len(c.EnabledCloudwatchLogsExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		}))
	checker.Register(LoggingCheck("aurora-mysql-cluster-audit-logging", "This rule checks configuration for Aurora MySQL cluster audit logging.", "rds", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-mysql") {
					continue
				}
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
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
		}))
	checker.Register(ConfigCheck("aurora-mysql-backtracking-enabled", "This rule checks Aurora MySQL backtracking enabled.", "rds", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-mysql") {
					continue
				}
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				window := int64(0)
				if c.BacktrackWindow != nil {
					window = *c.BacktrackWindow
				}
				ok := window > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("BacktrackWindow: %d", window)})
			}
			return res, nil
		}))
	checker.Register(LoggingCheck("rds-aurora-postgresql-logs-to-cloudwatch", "This rule checks Aurora PostgreSQL logs to CloudWatch.", "rds", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-postgresql") {
					continue
				}
				id := *c.DBClusterIdentifier
				logging := len(c.EnabledCloudwatchLogsExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		}))
	checker.Register(LoggingCheck("rds-postgresql-logs-to-cloudwatch", "This rule checks PostgreSQL logs to CloudWatch.", "rds", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "postgres") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				logging := len(inst.EnabledCloudwatchLogsExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		}))
	checker.Register(LoggingCheck("rds-sql-server-logs-to-cloudwatch", "This rule checks SQL Server logs to CloudWatch.", "rds", d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "sqlserver") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				logging := len(inst.EnabledCloudwatchLogsExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		}))

	// rds-instance-subnet-igw-check
	checker.Register(ConfigCheck(
		"rds-instance-subnet-igw-check",
		"This rule checks RDS instance subnet IGW.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			subnets, err := d.EC2Subnets.Get()
			if err != nil {
				return nil, err
			}
			subnetPublic := make(map[string]bool)
			for _, s := range subnets {
				if s.SubnetId == nil {
					continue
				}
				public := s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch
				subnetPublic[*s.SubnetId] = public
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				public := false
				if inst.DBSubnetGroup != nil {
					for _, sg := range inst.DBSubnetGroup.Subnets {
						if sg.SubnetIdentifier != nil && subnetPublic[*sg.SubnetIdentifier] {
							public = true
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public subnet: %v", public)})
			}
			return res, nil
		},
	))

	// rds-multi-az-support + rds-cluster-multi-az-enabled
	checker.Register(EnabledCheck(
		"rds-multi-az-support",
		"This rule checks RDS multi-AZ support.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				enabled := inst.MultiAZ != nil && *inst.MultiAZ
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))
	checker.Register(EnabledCheck(
		"rds-cluster-multi-az-enabled",
		"This rule checks RDS cluster multi-AZ enabled.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := "unknown"
				if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				enabled := len(c.AvailabilityZones) > 1
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-proxy-tls-encryption
	checker.Register(ConfigCheck(
		"rds-proxy-tls-encryption",
		"This rule checks RDS proxy TLS encryption.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			proxies, err := d.RDSProxies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range proxies {
				id := "unknown"
				if p.DBProxyName != nil {
					id = *p.DBProxyName
				}
				ok := p.RequireTLS != nil && *p.RequireTLS
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("RequireTLS: %v", p.RequireTLS)})
			}
			return res, nil
		},
	))

	// rds-snapshots-public-prohibited + rds-snapshot-encrypted
	checker.Register(ConfigCheck(
		"rds-snapshots-public-prohibited",
		"This rule checks RDS snapshots public prohibited.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.RDSSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range snaps {
				id := "unknown"
				if s.DBSnapshotIdentifier != nil {
					id = *s.DBSnapshotIdentifier
				}
				public := false
				detail := "Publicly accessible attribute not available"
				if s.SnapshotType != nil {
					detail = fmt.Sprintf("SnapshotType: %s", *s.SnapshotType)
				}
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"rds-snapshot-encrypted",
		"This rule checks RDS snapshot encrypted.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			snaps, err := d.RDSSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, s := range snaps {
				id := "unknown"
				if s.DBSnapshotIdentifier != nil {
					id = *s.DBSnapshotIdentifier
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: s.Encrypted != nil && *s.Encrypted})
			}
			return res, nil
		},
	))

	// rds-resources-protected-by-backup-plan + rds-in-backup-plan + rds-last-backup-recovery-point-created + rds-meets-restore-time-target
	checker.Register(ConfigCheck(
		"rds-resources-protected-by-backup-plan",
		"This rule checks RDS resources protected by backup plan.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceArn != nil {
					id = *inst.DBInstanceArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-in-backup-plan",
		"This rule checks RDS in backup plan.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceArn != nil {
					id = *inst.DBInstanceArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-last-backup-recovery-point-created",
		"This rule checks RDS last backup recovery point created.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				arn := ""
				if inst.DBInstanceArn != nil {
					arn = *inst.DBInstanceArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery point exists"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-meets-restore-time-target",
		"This rule checks RDS meets restore time target.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				arn := ""
				if inst.DBInstanceArn != nil {
					arn = *inst.DBInstanceArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points available"})
			}
			return res, nil
		},
	))

	// Aurora backup and encryption checks
	checker.Register(EncryptionCheck(
		"aurora-global-database-encryption-at-rest",
		"This rule checks Aurora global database encryption at rest.",
		"rds",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				if c.GlobalClusterIdentifier == nil {
					continue
				}
				id := "unknown"
				if c.DBClusterArn != nil {
					id = *c.DBClusterArn
				} else if c.DBClusterIdentifier != nil {
					id = *c.DBClusterIdentifier
				}
				encrypted := c.StorageEncrypted != nil && *c.StorageEncrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-last-backup-recovery-point-created",
		"This rule checks Aurora last backup recovery point created.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				arn := ""
				if c.DBClusterArn != nil {
					arn = *c.DBClusterArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery point exists"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-meets-restore-time-target",
		"This rule checks Aurora meets restore time target.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				arn := ""
				if c.DBClusterArn != nil {
					arn = *c.DBClusterArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points available"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-resources-in-logically-air-gapped-vault",
		"This rule checks Aurora resources in logically air gapped vault.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				arn := ""
				if c.DBClusterArn != nil {
					arn = *c.DBClusterArn
				}
				ok := false
				for _, rp := range rps[arn] {
					if string(rp.VaultType) == "LOGICALLY_AIR_GAPPED" {
						ok = true
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Air gapped vault recovery point"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-resources-protected-by-backup-plan",
		"This rule checks Aurora resources protected by backup plan.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				arn := ""
				if c.DBClusterArn != nil {
					arn = *c.DBClusterArn
				}
				_, ok := resources[arn]
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))

	// rds-db-security-group-not-allowed
	checker.Register(ConfigCheck(
		"rds-db-security-group-not-allowed",
		"This rule checks RDS DB security group not allowed.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				ok := len(inst.DBSecurityGroups) == 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "DBSecurityGroups empty"})
			}
			return res, nil
		},
	))

	// rds-mysql-instance-encrypted-in-transit + rds-postgres-instance-encrypted-in-transit + rds-mariadb-instance-encrypted-in-transit + rds-sqlserver-encrypted-in-transit
	checker.Register(ConfigCheck(
		"rds-mysql-instance-encrypted-in-transit",
		"This rule checks RDS MySQL instance encrypted in transit.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			params, err := d.RDSDBParamValues.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "mysql") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				ok := false
				for _, pg := range inst.DBParameterGroups {
					if pg.DBParameterGroupName == nil {
						continue
					}
					val := params[*pg.DBParameterGroupName]["require_secure_transport"]
					ok = ok || val == "ON" || val == "1" || strings.EqualFold(val, "true")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "require_secure_transport enabled"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-mariadb-instance-encrypted-in-transit",
		"This rule checks RDS MariaDB instance encrypted in transit.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			params, err := d.RDSDBParamValues.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "mariadb") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				ok := false
				for _, pg := range inst.DBParameterGroups {
					if pg.DBParameterGroupName == nil {
						continue
					}
					val := params[*pg.DBParameterGroupName]["rds.force_ssl"]
					ok = ok || val == "1" || strings.EqualFold(val, "on") || strings.EqualFold(val, "true")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "rds.force_ssl enabled"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-postgres-instance-encrypted-in-transit",
		"This rule checks RDS PostgreSQL instance encrypted in transit.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			params, err := d.RDSDBParamValues.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "postgres") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				ok := false
				for _, pg := range inst.DBParameterGroups {
					if pg.DBParameterGroupName == nil {
						continue
					}
					val := params[*pg.DBParameterGroupName]["rds.force_ssl"]
					ok = ok || val == "1" || strings.EqualFold(val, "on") || strings.EqualFold(val, "true")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "rds.force_ssl enabled"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-sqlserver-encrypted-in-transit",
		"This rule checks RDS SQL Server encrypted in transit.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			params, err := d.RDSDBParamValues.Get()
			if err != nil {
				return nil, err
			}
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				if inst.Engine == nil || !strings.Contains(*inst.Engine, "sqlserver") {
					continue
				}
				id := *inst.DBInstanceIdentifier
				ok := false
				for _, pg := range inst.DBParameterGroups {
					if pg.DBParameterGroupName == nil {
						continue
					}
					val := params[*pg.DBParameterGroupName]["rds.force_ssl"]
					ok = ok || val == "1" || strings.EqualFold(val, "on") || strings.EqualFold(val, "true")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "rds.force_ssl enabled"})
			}
			return res, nil
		},
	))

	// rds-mysql-cluster-copy-tags-to-snapshot-check + rds-pgsql-cluster-copy-tags-to-snapshot-check
	checker.Register(ConfigCheck(
		"rds-mysql-cluster-copy-tags-to-snapshot-check",
		"This rule checks RDS MySQL cluster copy tags to snapshot.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-mysql") {
					continue
				}
				id := *c.DBClusterIdentifier
				ok := c.CopyTagsToSnapshot != nil && *c.CopyTagsToSnapshot
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CopyTagsToSnapshot: %v", c.CopyTagsToSnapshot)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-pgsql-cluster-copy-tags-to-snapshot-check",
		"This rule checks RDS PostgreSQL cluster copy tags to snapshot.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RDSDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				if c.Engine == nil || !strings.Contains(*c.Engine, "aurora-postgresql") {
					continue
				}
				id := *c.DBClusterIdentifier
				ok := c.CopyTagsToSnapshot != nil && *c.CopyTagsToSnapshot
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CopyTagsToSnapshot: %v", c.CopyTagsToSnapshot)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"mariadb-publish-logs-to-cloudwatch-logs",
		"This rule checks mariadb publish logs to cloudwatch logs.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			instances, err := d.RDSDBInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range instances {
				if inst.Engine == nil || *inst.Engine != "mariadb" {
					continue
				}
				id := "unknown"
				if inst.DBInstanceIdentifier != nil {
					id = *inst.DBInstanceIdentifier
				}
				ok := len(inst.EnabledCloudwatchLogsExports) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Log exports: %d", len(inst.EnabledCloudwatchLogsExports))})
			}
			return res, nil
		},
	))
}
