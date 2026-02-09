package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
)

func RegisterElastiCacheChecks(d *awsdata.Data) {
	// elasticache-automatic-backup-check-enabled + elasticache-redis-cluster-automatic-backup-check
	checker.Register(ConfigCheck(
		"elasticache-automatic-backup-check-enabled",
		"This rule checks ElastiCache automatic backup enabled.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				ok := c.SnapshotRetentionLimit != nil && *c.SnapshotRetentionLimit > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SnapshotRetentionLimit: %v", c.SnapshotRetentionLimit)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"elasticache-redis-cluster-automatic-backup-check",
		"This rule checks ElastiCache Redis cluster automatic backup.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				ok := rg.SnapshotRetentionLimit != nil && *rg.SnapshotRetentionLimit > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SnapshotRetentionLimit: %v", rg.SnapshotRetentionLimit)})
			}
			return res, nil
		},
	))

	// elasticache-auto-minor-version-upgrade-check
	checker.Register(ConfigCheck(
		"elasticache-auto-minor-version-upgrade-check",
		"This rule checks ElastiCache auto minor version upgrade.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				ok := c.AutoMinorVersionUpgrade != nil && *c.AutoMinorVersionUpgrade
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AutoMinorVersionUpgrade: %v", c.AutoMinorVersionUpgrade)})
			}
			return res, nil
		},
	))

	// elasticache-repl-grp-auto-failover-enabled
	checker.Register(EnabledCheck(
		"elasticache-repl-grp-auto-failover-enabled",
		"This rule checks ElastiCache replication group auto failover enabled.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				enabled := rg.AutomaticFailover == elasticachetypes.AutomaticFailoverStatusEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// elasticache-repl-grp-encrypted-at-rest + elasticache-repl-grp-encrypted-in-transit + elasticache-rbac-auth-enabled + elasticache-repl-grp-redis-auth-enabled
	checker.Register(EncryptionCheck(
		"elasticache-repl-grp-encrypted-at-rest",
		"This rule checks ElastiCache replication group encrypted at rest.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: rg.AtRestEncryptionEnabled})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"elasticache-repl-grp-encrypted-in-transit",
		"This rule checks ElastiCache replication group encrypted in transit.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: rg.TransitEncryptionEnabled})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"elasticache-rbac-auth-enabled",
		"This rule checks ElastiCache RBAC auth enabled.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				ok := len(rg.UserGroupIds) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("UserGroupIds: %d", len(rg.UserGroupIds))})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"elasticache-repl-grp-redis-auth-enabled",
		"This rule checks ElastiCache replication group Redis auth enabled.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				ok := rg.AuthTokenEnabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AuthTokenEnabled: %v", ok)})
			}
			return res, nil
		},
	))

	// elasticache-subnet-group-check
	checker.Register(ConfigCheck(
		"elasticache-subnet-group-check",
		"This rule checks ElastiCache subnet group.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			subnets, err := d.ElastiCacheSubnetGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, sg := range subnets {
				id := "unknown"
				if sg.CacheSubnetGroupName != nil {
					id = *sg.CacheSubnetGroupName
				}
				ok := len(sg.Subnets) > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Subnet count: %d", len(sg.Subnets))})
			}
			return res, nil
		},
	))

	// elasticache-supported-engine-version
	checker.Register(ConfigCheck(
		"elasticache-supported-engine-version",
		"This rule checks ElastiCache supported engine version.",
		"elasticache",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				ok := c.EngineVersion != nil && *c.EngineVersion != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("EngineVersion: %v", c.EngineVersion)})
			}
			return res, nil
		},
	))
}
