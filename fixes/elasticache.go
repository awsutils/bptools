package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
)

// ── elasticache-auto-minor-version-upgrade-check ──────────────────────────────

type elastiCacheAutoMinorVersionFix struct{ clients *awsdata.Clients }

func (f *elastiCacheAutoMinorVersionFix) CheckID() string {
	return "elasticache-auto-minor-version-upgrade-check"
}
func (f *elastiCacheAutoMinorVersionFix) Description() string {
	return "Enable auto minor version upgrades on ElastiCache cluster"
}
func (f *elastiCacheAutoMinorVersionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elastiCacheAutoMinorVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *elastiCacheAutoMinorVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ElastiCache.DescribeCacheClusters(fctx.Ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cache cluster: " + err.Error()
		return base
	}
	if len(out.CacheClusters) > 0 && out.CacheClusters[0].AutoMinorVersionUpgrade != nil && *out.CacheClusters[0].AutoMinorVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "auto minor version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable auto minor version upgrade on cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.ElastiCache.ModifyCacheCluster(fctx.Ctx, &elasticache.ModifyCacheClusterInput{
		CacheClusterId:          aws.String(resourceID),
		AutoMinorVersionUpgrade: aws.Bool(true),
		ApplyImmediately:        aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cache cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled auto minor version upgrade on cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── elasticache-repl-grp-auto-failover-enabled ────────────────────────────────

type elastiCacheAutoFailoverFix struct{ clients *awsdata.Clients }

func (f *elastiCacheAutoFailoverFix) CheckID() string {
	return "elasticache-repl-grp-auto-failover-enabled"
}
func (f *elastiCacheAutoFailoverFix) Description() string {
	return "Enable automatic failover on ElastiCache replication group"
}
func (f *elastiCacheAutoFailoverFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elastiCacheAutoFailoverFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elastiCacheAutoFailoverFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ElastiCache.DescribeReplicationGroups(fctx.Ctx, &elasticache.DescribeReplicationGroupsInput{
		ReplicationGroupId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe replication group: " + err.Error()
		return base
	}
	if len(out.ReplicationGroups) > 0 && out.ReplicationGroups[0].AutomaticFailover == elasticachetypes.AutomaticFailoverStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "automatic failover already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable automatic failover on replication group %s", resourceID)}
		return base
	}

	_, err = f.clients.ElastiCache.ModifyReplicationGroup(fctx.Ctx, &elasticache.ModifyReplicationGroupInput{
		ReplicationGroupId:    aws.String(resourceID),
		AutomaticFailoverEnabled: aws.Bool(true),
		ApplyImmediately:      aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify replication group: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled automatic failover on replication group %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── elasticache-automatic-backup-check-enabled ───────────────────────────────

type elastiCacheBackupFix struct{ clients *awsdata.Clients }

func (f *elastiCacheBackupFix) CheckID() string {
	return "elasticache-automatic-backup-check-enabled"
}
func (f *elastiCacheBackupFix) Description() string {
	return "Enable automatic backup on ElastiCache cluster"
}
func (f *elastiCacheBackupFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elastiCacheBackupFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elastiCacheBackupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ElastiCache.DescribeCacheClusters(fctx.Ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cache cluster: " + err.Error()
		return base
	}
	if len(out.CacheClusters) > 0 && out.CacheClusters[0].SnapshotRetentionLimit != nil && *out.CacheClusters[0].SnapshotRetentionLimit > 0 {
		base.Status = fix.FixSkipped
		base.Message = "automatic backup already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set SnapshotRetentionLimit=1 on ElastiCache cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.ElastiCache.ModifyCacheCluster(fctx.Ctx, &elasticache.ModifyCacheClusterInput{
		CacheClusterId:         aws.String(resourceID),
		SnapshotRetentionLimit: aws.Int32(1),
		ApplyImmediately:       aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cache cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set SnapshotRetentionLimit=1 on ElastiCache cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── elasticache-redis-cluster-automatic-backup-check ─────────────────────────

type elastiCacheRedisBackupFix struct{ clients *awsdata.Clients }

func (f *elastiCacheRedisBackupFix) CheckID() string {
	return "elasticache-redis-cluster-automatic-backup-check"
}
func (f *elastiCacheRedisBackupFix) Description() string {
	return "Enable automatic backup on ElastiCache Redis cluster"
}
func (f *elastiCacheRedisBackupFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *elastiCacheRedisBackupFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *elastiCacheRedisBackupFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Try replication group first
	rgOut, err := f.clients.ElastiCache.DescribeReplicationGroups(fctx.Ctx, &elasticache.DescribeReplicationGroupsInput{
		ReplicationGroupId: aws.String(resourceID),
	})
	if err == nil && len(rgOut.ReplicationGroups) > 0 {
		rg := rgOut.ReplicationGroups[0]
		if rg.SnapshotRetentionLimit != nil && *rg.SnapshotRetentionLimit >= 15 {
			base.Status = fix.FixSkipped
			base.Message = "automatic backup already enabled (SnapshotRetentionLimit >= 15)"
			return base
		}
		if fctx.DryRun {
			base.Status = fix.FixDryRun
			base.Steps = []string{fmt.Sprintf("would set SnapshotRetentionLimit=15 on replication group %s", resourceID)}
			return base
		}
		_, err = f.clients.ElastiCache.ModifyReplicationGroup(fctx.Ctx, &elasticache.ModifyReplicationGroupInput{
			ReplicationGroupId:     aws.String(resourceID),
			SnapshotRetentionLimit: aws.Int32(15),
			ApplyImmediately:       aws.Bool(true),
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "modify replication group: " + err.Error()
			return base
		}
		base.Steps = []string{fmt.Sprintf("set SnapshotRetentionLimit=15 on replication group %s", resourceID)}
		base.Status = fix.FixApplied
		return base
	}

	// Fall back to cache cluster
	clOut, err := f.clients.ElastiCache.DescribeCacheClusters(fctx.Ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cache cluster: " + err.Error()
		return base
	}
	if len(clOut.CacheClusters) > 0 && clOut.CacheClusters[0].SnapshotRetentionLimit != nil && *clOut.CacheClusters[0].SnapshotRetentionLimit >= 15 {
		base.Status = fix.FixSkipped
		base.Message = "automatic backup already enabled (SnapshotRetentionLimit >= 15)"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set SnapshotRetentionLimit=15 on ElastiCache cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.ElastiCache.ModifyCacheCluster(fctx.Ctx, &elasticache.ModifyCacheClusterInput{
		CacheClusterId:         aws.String(resourceID),
		SnapshotRetentionLimit: aws.Int32(15),
		ApplyImmediately:       aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify cache cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set SnapshotRetentionLimit=15 on ElastiCache cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
