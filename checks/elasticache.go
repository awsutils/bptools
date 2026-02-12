package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
				ok := rg.SnapshotRetentionLimit != nil && *rg.SnapshotRetentionLimit >= 15
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SnapshotRetentionLimit: %v", rg.SnapshotRetentionLimit)})
			}
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				engine := elasticacheEngine(c.Engine)
				if engine != "redis" && engine != "valkey" {
					continue
				}
				ok := c.SnapshotRetentionLimit != nil && *c.SnapshotRetentionLimit >= 15
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SnapshotRetentionLimit: %v", c.SnapshotRetentionLimit)})
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
				engine := elasticacheEngine(c.Engine)
				if engine != "redis" && engine != "valkey" {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: fmt.Sprintf("Not applicable for engine: %s", engine)})
					continue
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
				res = append(res, EncryptionResource{ID: id, Encrypted: rg.AtRestEncryptionEnabled != nil && *rg.AtRestEncryptionEnabled})
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
				res = append(res, EncryptionResource{ID: id, Encrypted: rg.TransitEncryptionEnabled != nil && *rg.TransitEncryptionEnabled})
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
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			clusterVersions := elasticacheClusterVersionMap(clusters)
			var res []ConfigResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				if !elasticacheReplicationGroupVersionAtLeast(rg.MemberClusters, clusterVersions, 6, 0) {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Not applicable for replication groups below version 6"})
					continue
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
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			clusterVersions := elasticacheClusterVersionMap(clusters)
			var res []ConfigResource
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				if elasticacheReplicationGroupVersionAtLeast(rg.MemberClusters, clusterVersions, 6, 0) {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "Not applicable for replication groups version 6+"})
					continue
				}
				ok := rg.AuthTokenEnabled != nil && *rg.AuthTokenEnabled
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
			clusters, err := d.ElastiCacheClusters.Get()
			if err != nil {
				return nil, err
			}
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			clusterSubnetGroups := make(map[string]string)
			for _, c := range clusters {
				if c.CacheClusterId == nil {
					continue
				}
				group := ""
				if c.CacheSubnetGroupName != nil {
					group = strings.TrimSpace(strings.ToLower(*c.CacheSubnetGroupName))
				}
				clusterSubnetGroups[*c.CacheClusterId] = group
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				group := ""
				if c.CacheSubnetGroupName != nil {
					group = strings.TrimSpace(strings.ToLower(*c.CacheSubnetGroupName))
				}
				ok := group != "" && group != "default"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CacheSubnetGroupName: %s", group)})
			}
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				ok := len(rg.MemberClusters) > 0
				group := ""
				for _, member := range rg.MemberClusters {
					memberGroup := clusterSubnetGroups[member]
					if memberGroup == "" {
						ok = false
						break
					}
					if group == "" {
						group = memberGroup
					}
					if memberGroup == "default" {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CacheSubnetGroupName: %s", group)})
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
			repls, err := d.ElastiCacheReplGroups.Get()
			if err != nil {
				return nil, err
			}
			clusterVersions := elasticacheClusterVersionMap(clusters)
			clusterEngines := elasticacheClusterEngineMap(clusters)
			var res []ConfigResource
			for _, c := range clusters {
				id := "unknown"
				if c.CacheClusterId != nil {
					id = *c.CacheClusterId
				}
				engine := elasticacheEngine(c.Engine)
				version := elasticacheVersion(c.EngineVersion)
				ok := true
				detail := fmt.Sprintf("Engine: %s Version: %s", engine, version)
				switch engine {
				case "redis":
					minMajor, minMinor := elasticacheMinVersionFromEnv("BPTOOLS_ELASTICACHE_MIN_REDIS_VERSION", 6, 0)
					ok = elasticacheVersionAtLeast(c.EngineVersion, minMajor, minMinor)
				case "valkey":
					minMajor, minMinor := elasticacheMinVersionFromEnv("BPTOOLS_ELASTICACHE_MIN_VALKEY_VERSION", 7, 2)
					ok = elasticacheVersionAtLeast(c.EngineVersion, minMajor, minMinor)
				case "memcached":
					minMajor, minMinor := elasticacheMinVersionFromEnv("BPTOOLS_ELASTICACHE_MIN_MEMCACHED_VERSION", 1, 6)
					ok = elasticacheVersionAtLeast(c.EngineVersion, minMajor, minMinor)
				default:
					ok = c.EngineVersion != nil && *c.EngineVersion != ""
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			for _, rg := range repls {
				id := "unknown"
				if rg.ReplicationGroupId != nil {
					id = *rg.ReplicationGroupId
				}
				engine := elasticacheReplicationGroupEngine(rg.MemberClusters, clusterEngines)
				version := elasticacheReplicationGroupVersion(rg.MemberClusters, clusterVersions)
				ok := true
				detail := fmt.Sprintf("Engine: %s Version: %s", engine, version)
				switch engine {
				case "redis":
					minMajor, minMinor := elasticacheMinVersionFromEnv("BPTOOLS_ELASTICACHE_MIN_REDIS_VERSION", 6, 0)
					ok = elasticacheReplicationGroupVersionAtLeast(rg.MemberClusters, clusterVersions, minMajor, minMinor)
				case "valkey":
					minMajor, minMinor := elasticacheMinVersionFromEnv("BPTOOLS_ELASTICACHE_MIN_VALKEY_VERSION", 7, 2)
					ok = elasticacheReplicationGroupVersionAtLeast(rg.MemberClusters, clusterVersions, minMajor, minMinor)
				default:
					ok = version != ""
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
}

func elasticacheEngine(engine *string) string {
	if engine == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(*engine))
}

func elasticacheVersion(version *string) string {
	if version == nil {
		return ""
	}
	return strings.TrimSpace(*version)
}

func elasticacheVersionParts(version *string) (int, int, bool) {
	value := elasticacheVersion(version)
	if value == "" {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorDigits := ""
	for _, ch := range parts[1] {
		if ch >= '0' && ch <= '9' {
			minorDigits += string(ch)
		} else {
			break
		}
	}
	if minorDigits == "" {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func elasticacheVersionAtLeast(version *string, minMajor int, minMinor int) bool {
	major, minor, ok := elasticacheVersionParts(version)
	if !ok {
		return false
	}
	if major != minMajor {
		return major > minMajor
	}
	return minor >= minMinor
}

func elasticacheMinVersionFromEnv(envVar string, defaultMajor int, defaultMinor int) (int, int) {
	value := strings.TrimSpace(os.Getenv(envVar))
	if value == "" {
		return defaultMajor, defaultMinor
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return defaultMajor, defaultMinor
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return defaultMajor, defaultMinor
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return defaultMajor, defaultMinor
	}
	return major, minor
}

func elasticacheClusterVersionMap(clusters []elasticachetypes.CacheCluster) map[string]*string {
	out := make(map[string]*string)
	for _, cluster := range clusters {
		if cluster.CacheClusterId == nil {
			continue
		}
		out[*cluster.CacheClusterId] = cluster.EngineVersion
	}
	return out
}

func elasticacheClusterEngineMap(clusters []elasticachetypes.CacheCluster) map[string]string {
	out := make(map[string]string)
	for _, cluster := range clusters {
		if cluster.CacheClusterId == nil {
			continue
		}
		out[*cluster.CacheClusterId] = elasticacheEngine(cluster.Engine)
	}
	return out
}

func elasticacheReplicationGroupEngine(memberClusters []string, clusterEngines map[string]string) string {
	for _, clusterID := range memberClusters {
		if engine, ok := clusterEngines[clusterID]; ok && engine != "" {
			return engine
		}
	}
	return ""
}

func elasticacheReplicationGroupVersion(memberClusters []string, clusterVersions map[string]*string) string {
	for _, clusterID := range memberClusters {
		if version, ok := clusterVersions[clusterID]; ok && version != nil && *version != "" {
			return elasticacheVersion(version)
		}
	}
	return ""
}

func elasticacheReplicationGroupVersionAtLeast(memberClusters []string, clusterVersions map[string]*string, minMajor int, minMinor int) bool {
	if len(memberClusters) == 0 {
		return false
	}
	for _, clusterID := range memberClusters {
		version, ok := clusterVersions[clusterID]
		if !ok || !elasticacheVersionAtLeast(version, minMajor, minMinor) {
			return false
		}
	}
	return true
}
