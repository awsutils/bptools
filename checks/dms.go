package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

func RegisterDMSChecks(d *awsdata.Data) {
	// dms-auto-minor-version-upgrade-check
	checker.Register(ConfigCheck(
		"dms-auto-minor-version-upgrade-check",
		"Checks if an AWS Database Migration Service (AWS DMS) replication instance has automatic minor version upgrades enabled. The rule is NON_COMPLIANT if an AWS DMS replication instance is not configured with automatic minor version upgrades.",
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
		"Checks if AWS Database Migration Service (AWS DMS) endpoints are configured with an SSL connection. The rule is NON_COMPLIANT if AWS DMS does not have an SSL connection configured.",
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
		"Checks if AWS DMS endpoints have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS Database Migration Service (AWS DMS) endpoints for MongoDb data stores are enabled for password-based authentication and access control. The rule is NON_COMPLIANT if password-based authentication and access control is not enabled.",
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
				authType := dmstypes.AuthTypeValueNo
				if e.MongoDbSettings != nil {
					authType = e.MongoDbSettings.AuthType
				}
				ok := authType == dmstypes.AuthTypeValuePassword
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("MongoDb AuthType: %s", authType)})
			}
			return res, nil
		},
	))

	// dms-neptune-iam-authorization-enabled
	checker.Register(ConfigCheck(
		"dms-neptune-iam-authorization-enabled",
		"Checks if an AWS Database Migration Service (AWS DMS) endpoint for Amazon Neptune databases is configured with IAM authorization. The rule is NON_COMPLIANT if an AWS DMS endpoint where Neptune is the target has IamAuthEnabled set to false.",
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
		"Checks if AWS Database Migration Service (AWS DMS) endpoints for Redis data stores are enabled for TLS/SSL encryption of data communicated with other endpoints. The rule is NON_COMPLIANT if TLS/SSL encryption is not enabled.",
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
				protocol := dmstypes.SslSecurityProtocolValuePlaintext
				if e.RedisSettings != nil {
					protocol = e.RedisSettings.SslSecurityProtocol
				}
				ok := protocol == dmstypes.SslSecurityProtocolValueSslEncryption
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Redis SslSecurityProtocol: %s", protocol)})
			}
			return res, nil
		},
	))

	// dms-replication-instance-multi-az-enabled
	checker.Register(EnabledCheck(
		"dms-replication-instance-multi-az-enabled",
		"Checks if AWS Database Migration Service (DMS) replication instances are configured with multiple Availability Zones. The rule is NON_COMPLIANT if a DMS replication instance is not configured to use multiple Availability Zones.",
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
		"Checks if AWS Database Migration Service (AWS DMS) replication instances are public. The rule is NON_COMPLIANT if PubliclyAccessible field is set to true.",
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
		"Checks if logging is enabled with a valid severity level for AWS DMS replication tasks of a source database. The rule is NON_COMPLIANT if logging is not enabled or logs for DMS replication tasks of a source database have a severity level that is not valid.",
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
				ok, detail := dmsReplicationTaskLoggingCheck(t.ReplicationTaskSettings, true)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	// dms-replication-task-targetdb-logging
	checker.Register(ConfigCheck(
		"dms-replication-task-targetdb-logging",
		"Checks if logging is enabled with a valid severity level for AWS DMS replication task events of a target database. The rule is NON_COMPLIANT if logging is not enabled or replication task logging of a target database has a severity level that is not valid.",
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
				ok, detail := dmsReplicationTaskLoggingCheck(t.ReplicationTaskSettings, false)
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	// dms-replication-task-tagged
	checker.Register(TaggedCheck(
		"dms-replication-task-tagged",
		"Checks if AWS DMS replication tasks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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

func dmsReplicationTaskLoggingCheck(taskSettings *string, source bool) (bool, string) {
	if taskSettings == nil || *taskSettings == "" {
		return false, "Missing ReplicationTaskSettings"
	}

	var settings struct {
		Logging struct {
			EnableLogging bool `json:"EnableLogging"`
			LogComponents []struct {
				Id       string `json:"Id"`
				Severity string `json:"Severity"`
			} `json:"LogComponents"`
		} `json:"Logging"`
	}
	if err := json.Unmarshal([]byte(*taskSettings), &settings); err != nil {
		return false, fmt.Sprintf("Invalid ReplicationTaskSettings JSON: %v", err)
	}
	if !settings.Logging.EnableLogging {
		return false, "EnableLogging=false"
	}

	componentIDs := map[string]bool{}
	if source {
		componentIDs["SOURCE_CAPTURE"] = false
		componentIDs["SOURCE_UNLOAD"] = false
		componentIDs["SOURCE_LOAD"] = false
	} else {
		componentIDs["TARGET_LOAD"] = false
		componentIDs["TARGET_APPLY"] = false
		componentIDs["TARGET_LOAD_ORDER"] = false
	}
	validSeverity := map[string]bool{
		"LOGGER_SEVERITY_DEFAULT":        true,
		"LOGGER_SEVERITY_DEBUG":          true,
		"LOGGER_SEVERITY_INFO":           true,
		"LOGGER_SEVERITY_WARNING":        true,
		"LOGGER_SEVERITY_ERROR":          true,
		"LOGGER_SEVERITY_DETAILED_DEBUG": true,
	}

	for _, component := range settings.Logging.LogComponents {
		_, required := componentIDs[component.Id]
		if !required {
			continue
		}
		if validSeverity[component.Severity] {
			componentIDs[component.Id] = true
		}
	}
	missing := []string{}
	for id, present := range componentIDs {
		if !present {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		if source {
			return true, "EnableLogging=true with required source log components and valid severity"
		}
		return true, "EnableLogging=true with required target log components and valid severity"
	}
	if source {
		return false, fmt.Sprintf("EnableLogging=true but missing/invalid source components: %v", missing)
	}
	return false, fmt.Sprintf("EnableLogging=true but missing/invalid target components: %v", missing)
}
