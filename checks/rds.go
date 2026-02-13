package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

var rdsDefaultAdmins = map[string]bool{"admin": true, "root": true, "master": true, "rdsadmin": true, "postgres": true}

func RegisterRDSChecks(d *awsdata.Data) {
	// rds-storage-encrypted
	checker.Register(EncryptionCheck(
		"rds-storage-encrypted",
		"Checks if storage encryption is enabled for your Amazon Relational Database Service (Amazon RDS) DB instances. The rule is NON_COMPLIANT if storage encryption is not enabled.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) cluster is encrypted at rest. The rule is NON_COMPLIANT if an Amazon RDS cluster is not encrypted at rest.",
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
		"Checks if the Amazon Relational Database Service (Amazon RDS) instances are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the instance configuration item.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have deletion protection enabled; for example, deletionProtection is set to false.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled. This rule is NON_COMPLIANT if an RDS cluster does not have deletion protection enabled.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have IAM authentication enabled.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) cluster has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS Cluster does not have IAM authentication enabled.",
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
		"Checks if Amazon Relational Database Service (RDS) database instances are configured for automatic minor version upgrades. The rule is NON_COMPLIANT if the value of 'autoMinorVersionUpgrade' is false.",
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
		"Checks if automatic minor version upgrades are enabled for Amazon RDS Multi-AZ cluster deployments. The rule is NON_COMPLIANT if autoMinorVersionUpgrade is set to false.",
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
		"Checks if enhanced monitoring is enabled for Amazon RDS instances. This rule is NON_COMPLIANT if 'monitoringInterval' is '0' in the configuration item of the RDS instance, or if 'monitoringInterval' does not match the rule parameter value.",
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
		"Checks if Amazon RDS event subscriptions have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon RDS option group resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) database has changed the admin username from its default value. This rule will only run on RDS database instances. The rule is NON_COMPLIANT if the admin username is set to the default value.",
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
		"Checks if an Amazon Relational Database Service (Amazon RDS) database cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username is set to the default value.",
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
		"Checks if respective logs of Amazon Relational Database Service (Amazon RDS) are enabled. The rule is NON_COMPLIANT if any log types are not enabled.",
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
				logging := rdsHasRequiredLogExports(inst.Engine, inst.EnabledCloudwatchLogsExports)
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(LoggingCheck("rds-aurora-mysql-audit-logging-enabled", "Checks if Amazon Aurora MySQL-Compatible Edition clusters are configured to publish audit logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if Aurora MySQL-Compatible Edition clusters do not have audit log publishing configured.", "rds", d,
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
	checker.Register(LoggingCheck("aurora-mysql-cluster-audit-logging", "Checks if Amazon Aurora MySQL DB clusters have audit logging enabled. The rule is NON_COMPLIANT if a DB cluster does not have audit logging enabled.", "rds", d,
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
	checker.Register(ConfigCheck("aurora-mysql-backtracking-enabled", "Checks if an Amazon Aurora MySQL cluster has backtracking enabled. The rule is NON_COMPLIANT if the Aurora cluster uses MySQL and it does not have backtracking enabled.", "rds", d,
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
	checker.Register(LoggingCheck("rds-aurora-postgresql-logs-to-cloudwatch", "Checks if an Amazon Aurora PostgreSQL DB cluster is configured to publish PostgreSQL logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the DB cluster is not configured to publish PostgreSQL logs to Amazon CloudWatch Logs.", "rds", d,
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
	checker.Register(LoggingCheck("rds-postgresql-logs-to-cloudwatch", "Checks if an Amazon PostgreSQL DB instance is configured to publish logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if the DB instance is not configured to publish logs to Amazon CloudWatch Logs.", "rds", d,
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
	checker.Register(LoggingCheck("rds-sql-server-logs-to-cloudwatch", "Checks if an Amazon SQL Server DB instance is configured to publish logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the DB instance is not configured to publish logs to Amazon CloudWatch Logs.", "rds", d,
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
		"Checks if RDS DB instances are deployed in a public subnet with a route to the internet gateway. The rule is NON_COMPLIANT if RDS DB instances is deployed in a public subnet",
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
			routeTables, err := d.EC2RouteTables.Get()
			if err != nil {
				return nil, err
			}
			subnetPublic := rdsSubnetHasInternetGatewayRoute(subnets, routeTables)
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
		"Checks whether high availability is enabled for your RDS DB instances.",
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
		"Checks if Multi-Availability Zone (Multi-AZ) replication is enabled on Amazon Aurora and Multi-AZ DB clusters managed by Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if an Amazon RDS instance is not configured with Multi-AZ.",
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
				enabled := c.MultiAZ != nil && *c.MultiAZ
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// rds-proxy-tls-encryption
	checker.Register(ConfigCheck(
		"rds-proxy-tls-encryption",
		"Checks if Amazon RDS proxies enforce TLS for all connections. The rule is NON_COMPLIANT if an Amazon RDS proxy does not have TLS enforced for all connections.",
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
		"Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is NON_COMPLIANT if any existing and new Amazon RDS snapshots are public.",
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
				if s.DBSnapshotIdentifier == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing DBSnapshotIdentifier"})
					continue
				}
				out, err := d.Clients.RDS.DescribeDBSnapshotAttributes(d.Ctx, &rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: s.DBSnapshotIdentifier})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("DescribeDBSnapshotAttributes failed: %v", err)})
					continue
				}
				public := rdsSnapshotAttributesIncludePublic(out.DBSnapshotAttributesResult.DBSnapshotAttributes)
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public restore access: %v", public)})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"rds-snapshot-encrypted",
		"Checks if Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. The rule is NON_COMPLIANT if the Amazon RDS DB snapshots are not encrypted.",
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
		"Checks if Amazon Relational Database Service (Amazon RDS) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon RDS Database instance is not covered by a backup plan.",
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
		"Checks if Amazon Relational Database Service (Amazon RDS) databases are present in AWS Backup plans. The rule is NON_COMPLIANT if Amazon RDS databases are not included in any AWS Backup plan.",
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
		"Checks if a recovery point was created for Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if the Amazon RDS instance does not have a corresponding recovery point created within the specified time period.",
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
				ok, detail := backupRecencyResult(rps[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-meets-restore-time-target",
		"Checks if the restore time of Amazon Relational Database Service (Amazon RDS) instances meets specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon RDS instance is greater than maxRestoreTime minutes.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
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
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	// Aurora backup and encryption checks
	checker.Register(EncryptionCheck(
		"aurora-global-database-encryption-at-rest",
		"Checks if Amazon Aurora Global Databases have storage encryption enabled. This rule is NON_COMPLIANT if an Amazon Aurora Global Database does not have storage encryption enabled.",
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
		"Checks if a recovery point was created for Amazon Aurora DB clusters. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) DB Cluster does not have a corresponding recovery point created within the specified time period.",
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
				ok, detail := backupRecencyResult(rps[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-meets-restore-time-target",
		"Checks if the restore time of Amazon Aurora DB clusters meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Aurora DB Cluster is greater than maxRestoreTime minutes.",
		"rds",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
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
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-resources-in-logically-air-gapped-vault",
		"Checks if Amazon Aurora DB clusters are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon Aurora DB cluster is not in a logically air-gapped vault within the specified time period.",
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
				ok, detail := airGappedRecencyResult(rps[arn], backupAirGappedRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"aurora-resources-protected-by-backup-plan",
		"Checks if Amazon Aurora DB clusters are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) Database Cluster is not protected by a backup plan.",
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
		"Checks if there are any Amazon Relational Database Service (Amazon RDS) DB security groups that are not the default DB security group. The rule is NON_COMPLIANT if there are any DB security groups that are not the default DB security group.",
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
		"Checks if connections to Amazon RDS for MySQL database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the associated database parameter group is not in-sync or if the require_secure_transport parameter is not set to 1.",
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
		"Checks if connections to Amazon RDS for MariaDB DB instances with engine version greater than or equal to 10.5 use encryption in transit. The rule is NON_COMPLIANT if the DB parameter group is not in-sync or if require_secure_transport is not set to ON.",
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
					val := params[*pg.DBParameterGroupName]["require_secure_transport"]
					ok = ok || val == "1" || strings.EqualFold(val, "on") || strings.EqualFold(val, "true")
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "require_secure_transport enabled"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"rds-postgres-instance-encrypted-in-transit",
		"Checks if connections to Amazon RDS PostgreSQL database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the associated database parameter group is not in-sync or if the rds.force_ssl parameter is not set to 1.",
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
		"Checks if connections to Amazon RDS SQL server database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the DB parameter force_ssl for the parameter group is not set to 1 or the ApplyStatus parameter is not 'in-sync'.",
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
		"Checks if Amazon Relational Database Service (Amazon RDS) MySQL DB clusters are configured to copy tags to snapshots. The rule is NON_COMPLIANT if an Amazon RDS MySQL DB cluster is not configured to copy tags to snapshots.",
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
		"Checks if Amazon Relational Database Service (Amazon RDS) PostgreSQL DB clusters are configured to copy tags to snapshots. The rule is NON_COMPLIANT if an RDS PostgreSQL DB cluster's CopyTagsToSnapshot property is set to false.",
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
		"Checks if Amazon MariaDB database instances are configured to publish logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if a database instance is not configured to publish logs to CloudWatch Logs.",
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

func rdsHasRequiredLogExports(engine *string, exports []string) bool {
	engineName := ""
	if engine != nil {
		engineName = strings.ToLower(strings.TrimSpace(*engine))
	}

	required := []string{}
	switch {
	case strings.Contains(engineName, "aurora-mysql"):
		required = []string{"audit"}
	case strings.Contains(engineName, "aurora-postgresql"), strings.Contains(engineName, "postgres"):
		required = []string{"postgresql"}
	case strings.Contains(engineName, "sqlserver"):
		required = []string{"error"}
	case strings.Contains(engineName, "mysql"), strings.Contains(engineName, "mariadb"):
		required = []string{"error", "general", "slowquery"}
	default:
		return len(exports) > 0
	}

	exported := map[string]bool{}
	for _, e := range exports {
		exported[strings.ToLower(strings.TrimSpace(e))] = true
	}
	for _, req := range required {
		if !exported[req] {
			return false
		}
	}
	return true
}

func rdsSnapshotAttributesIncludePublic(attrs []rdstypes.DBSnapshotAttribute) bool {
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

func rdsSubnetHasInternetGatewayRoute(subnets []ec2types.Subnet, routeTables []ec2types.RouteTable) map[string]bool {
	subnetToVPC := make(map[string]string)
	for _, subnet := range subnets {
		if subnet.SubnetId == nil || subnet.VpcId == nil {
			continue
		}
		subnetToVPC[*subnet.SubnetId] = *subnet.VpcId
	}

	mainRoutePublicByVPC := make(map[string]bool)
	explicitRoutePublicBySubnet := make(map[string]bool)
	for _, routeTable := range routeTables {
		routeTablePublic := routeTableHasInternetGatewayDefaultRoute(routeTable)
		vpcID := ""
		if routeTable.VpcId != nil {
			vpcID = *routeTable.VpcId
		}
		for _, assoc := range routeTable.Associations {
			if assoc.SubnetId != nil && *assoc.SubnetId != "" {
				explicitRoutePublicBySubnet[*assoc.SubnetId] = routeTablePublic
				continue
			}
			if assoc.Main != nil && *assoc.Main && vpcID != "" {
				mainRoutePublicByVPC[vpcID] = routeTablePublic
			}
		}
	}

	subnetPublic := make(map[string]bool)
	for subnetID, vpcID := range subnetToVPC {
		if val, ok := explicitRoutePublicBySubnet[subnetID]; ok {
			subnetPublic[subnetID] = val
			continue
		}
		subnetPublic[subnetID] = mainRoutePublicByVPC[vpcID]
	}
	return subnetPublic
}

func routeTableHasInternetGatewayDefaultRoute(routeTable ec2types.RouteTable) bool {
	for _, route := range routeTable.Routes {
		hasDefaultDestination := (route.DestinationCidrBlock != nil && *route.DestinationCidrBlock == "0.0.0.0/0") ||
			(route.DestinationIpv6CidrBlock != nil && *route.DestinationIpv6CidrBlock == "::/0")
		if !hasDefaultDestination {
			continue
		}
		if route.GatewayId != nil && strings.HasPrefix(strings.ToLower(*route.GatewayId), "igw-") {
			return true
		}
	}
	return false
}
