package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

func RegisterDMSChecks(d *awsdata.Data) {
	// dms-auto-minor-version-upgrade-check
	checker.Register(ConfigCheck(
		"dms-auto-minor-version-upgrade-check",
		"This rule checks DMS auto minor version upgrade.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			insts, err := d.DMSReplicationInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range insts {
				id := "unknown"
				if inst.ReplicationInstanceArn != nil {
					id = *inst.ReplicationInstanceArn
				}
				ok := inst.AutoMinorVersionUpgrade
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AutoMinorVersionUpgrade: %v", inst.AutoMinorVersionUpgrade)})
			}
			return res, nil
		},
	))

	// dms-endpoint-ssl-configured
	checker.Register(ConfigCheck(
		"dms-endpoint-ssl-configured",
		"This rule checks DMS endpoint SSL configured.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.DMSEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range eps {
				id := "unknown"
				if e.EndpointArn != nil {
					id = *e.EndpointArn
				}
				ssl := strings.ToLower(string(e.SslMode))
				ok := ssl != "none" && ssl != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SslMode: %s", e.SslMode)})
			}
			return res, nil
		},
	))

	// dms-endpoint-tagged
	checker.Register(TaggedCheck(
		"dms-endpoint-tagged",
		"This rule checks DMS endpoint tagged.",
		"dms",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			eps, err := d.DMSEndpoints.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.DMSEndpointTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, e := range eps {
				if e.EndpointArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *e.EndpointArn, Tags: tags[*e.EndpointArn]})
			}
			return res, nil
		},
	))

	// dms-mongo-db-authentication-enabled
	checker.Register(ConfigCheck(
		"dms-mongo-db-authentication-enabled",
		"This rule checks DMS MongoDB authentication enabled.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.DMSEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range eps {
				if e.EngineName == nil || !strings.Contains(strings.ToLower(*e.EngineName), "mongo") {
					continue
				}
				id := "unknown"
				if e.EndpointArn != nil {
					id = *e.EndpointArn
				}
				ok := e.Username != nil && *e.Username != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "MongoDB username set"})
			}
			return res, nil
		},
	))

	// dms-neptune-iam-authorization-enabled
	checker.Register(ConfigCheck(
		"dms-neptune-iam-authorization-enabled",
		"This rule checks DMS Neptune IAM authorization enabled.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.DMSEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range eps {
				if e.EngineName == nil || !strings.Contains(strings.ToLower(*e.EngineName), "neptune") {
					continue
				}
				id := "unknown"
				if e.EndpointArn != nil {
					id = *e.EndpointArn
				}
				ok := e.NeptuneSettings != nil && e.NeptuneSettings.IamAuthEnabled != nil && *e.NeptuneSettings.IamAuthEnabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("IamAuthEnabled: %v", ok)})
			}
			return res, nil
		},
	))

	// dms-redis-tls-enabled
	checker.Register(ConfigCheck(
		"dms-redis-tls-enabled",
		"This rule checks DMS Redis TLS enabled.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			eps, err := d.DMSEndpoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, e := range eps {
				if e.EngineName == nil || !strings.Contains(strings.ToLower(*e.EngineName), "redis") {
					continue
				}
				id := "unknown"
				if e.EndpointArn != nil {
					id = *e.EndpointArn
				}
				ssl := strings.ToLower(string(e.SslMode))
				ok := ssl != "none" && ssl != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("SslMode: %s", e.SslMode)})
			}
			return res, nil
		},
	))

	// dms-replication-instance-multi-az-enabled
	checker.Register(EnabledCheck(
		"dms-replication-instance-multi-az-enabled",
		"This rule checks DMS replication instance multi-AZ enabled.",
		"dms",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			insts, err := d.DMSReplicationInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range insts {
				id := "unknown"
				if inst.ReplicationInstanceArn != nil {
					id = *inst.ReplicationInstanceArn
				}
				res = append(res, EnabledResource{ID: id, Enabled: inst.MultiAZ})
			}
			return res, nil
		},
	))

	// dms-replication-not-public
	checker.Register(ConfigCheck(
		"dms-replication-not-public",
		"This rule checks DMS replication not public.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			insts, err := d.DMSReplicationInstances.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, inst := range insts {
				id := "unknown"
				if inst.ReplicationInstanceArn != nil {
					id = *inst.ReplicationInstanceArn
				}
				public := inst.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))

	// dms-replication-task-sourcedb-logging
	checker.Register(ConfigCheck(
		"dms-replication-task-sourcedb-logging",
		"This rule checks DMS replication task source DB logging.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.DMSReplicationTasks.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tasks {
				id := "unknown"
				if t.ReplicationTaskArn != nil {
					id = *t.ReplicationTaskArn
				}
				ok := t.ReplicationTaskSettings != nil && strings.Contains(*t.ReplicationTaskSettings, "LogComponents")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "ReplicationTaskSettings contains LogComponents"})
			}
			return res, nil
		},
	))

	// dms-replication-task-targetdb-logging
	checker.Register(ConfigCheck(
		"dms-replication-task-targetdb-logging",
		"This rule checks DMS replication task target DB logging.",
		"dms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			tasks, err := d.DMSReplicationTasks.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, t := range tasks {
				id := "unknown"
				if t.ReplicationTaskArn != nil {
					id = *t.ReplicationTaskArn
				}
				ok := t.ReplicationTaskSettings != nil && strings.Contains(*t.ReplicationTaskSettings, "LogComponents")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "ReplicationTaskSettings contains LogComponents"})
			}
			return res, nil
		},
	))

	// dms-replication-task-tagged
	checker.Register(TaggedCheck(
		"dms-replication-task-tagged",
		"This rule checks DMS replication task tagged.",
		"dms",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			tasks, err := d.DMSReplicationTasks.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.DMSReplicationTaskTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, t := range tasks {
				if t.ReplicationTaskArn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *t.ReplicationTaskArn, Tags: tags[*t.ReplicationTaskArn]})
			}
			return res, nil
		},
	))
}
