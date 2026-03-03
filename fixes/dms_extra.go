package fixes

import (
	"encoding/json"
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

// ── dms-endpoint-ssl-configured ───────────────────────────────────────────────

type dmsEndpointSSLFix struct{ clients *awsdata.Clients }

func (f *dmsEndpointSSLFix) CheckID() string     { return "dms-endpoint-ssl-configured" }
func (f *dmsEndpointSSLFix) Description() string { return "Enable SSL on DMS endpoint" }
func (f *dmsEndpointSSLFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dmsEndpointSSLFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *dmsEndpointSSLFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DMS.DescribeEndpoints(fctx.Ctx, &databasemigrationservice.DescribeEndpointsInput{
		Filters: []dmstypes.Filter{
			{Name: aws.String("endpoint-arn"), Values: []string{resourceID}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DMS endpoints: " + err.Error()
		return base
	}
	if len(out.Endpoints) == 0 {
		base.Status = fix.FixFailed
		base.Message = "endpoint not found: " + resourceID
		return base
	}
	ep := out.Endpoints[0]
	if ep.SslMode != dmstypes.DmsSslModeValueNone {
		base.Status = fix.FixSkipped
		base.Message = fmt.Sprintf("SSL already configured (mode: %s)", ep.SslMode)
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable SSL (require) on DMS endpoint %s", resourceID)}
		return base
	}

	_, err = f.clients.DMS.ModifyEndpoint(fctx.Ctx, &databasemigrationservice.ModifyEndpointInput{
		EndpointArn: aws.String(resourceID),
		SslMode:     dmstypes.DmsSslModeValueRequire,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DMS endpoint: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled SSL (require) on DMS endpoint %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── dms-replication-task-sourcedb-logging / dms-replication-task-targetdb-logging

type dmsReplicationTaskLoggingFix struct {
	checkID string
	source  bool
	clients *awsdata.Clients
}

func (f *dmsReplicationTaskLoggingFix) CheckID() string { return f.checkID }
func (f *dmsReplicationTaskLoggingFix) Description() string {
	if f.source {
		return "Enable source DB logging on DMS replication task"
	}
	return "Enable target DB logging on DMS replication task"
}
func (f *dmsReplicationTaskLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dmsReplicationTaskLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *dmsReplicationTaskLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DMS.DescribeReplicationTasks(fctx.Ctx, &databasemigrationservice.DescribeReplicationTasksInput{
		Filters: []dmstypes.Filter{
			{Name: aws.String("replication-task-arn"), Values: []string{resourceID}},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe DMS replication tasks: " + err.Error()
		return base
	}
	if len(out.ReplicationTasks) == 0 {
		base.Status = fix.FixFailed
		base.Message = "replication task not found: " + resourceID
		return base
	}
	task := out.ReplicationTasks[0]

	var requiredComponents []string
	if f.source {
		requiredComponents = []string{"SOURCE_CAPTURE", "SOURCE_UNLOAD", "SOURCE_LOAD"}
	} else {
		requiredComponents = []string{"TARGET_LOAD", "TARGET_APPLY", "TARGET_LOAD_ORDER"}
	}

	// Parse existing settings
	var settings map[string]interface{}
	if task.ReplicationTaskSettings != nil && *task.ReplicationTaskSettings != "" {
		if err := json.Unmarshal([]byte(*task.ReplicationTaskSettings), &settings); err != nil {
			base.Status = fix.FixFailed
			base.Message = "parse task settings: " + err.Error()
			return base
		}
	} else {
		settings = map[string]interface{}{}
	}

	// Idempotency check
	if loggingSection, ok := settings["Logging"].(map[string]interface{}); ok {
		if enabled, _ := loggingSection["EnableLogging"].(bool); enabled {
			components, _ := loggingSection["LogComponents"].([]interface{})
			found := map[string]bool{}
			for _, c := range components {
				if cm, ok := c.(map[string]interface{}); ok {
					id, _ := cm["Id"].(string)
					sev, _ := cm["Severity"].(string)
					if sev != "" && sev != "LOGGER_SEVERITY_OFF" {
						found[id] = true
					}
				}
			}
			allFound := true
			for _, r := range requiredComponents {
				if !found[r] {
					allFound = false
					break
				}
			}
			if allFound {
				base.Status = fix.FixSkipped
				base.Message = "logging already enabled with required components"
				return base
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable logging for %v on DMS task %s", requiredComponents, resourceID)}
		return base
	}

	// Build updated logging settings
	loggingSection, _ := settings["Logging"].(map[string]interface{})
	if loggingSection == nil {
		loggingSection = map[string]interface{}{}
	}
	loggingSection["EnableLogging"] = true

	existingComponents, _ := loggingSection["LogComponents"].([]interface{})
	componentMap := map[string]interface{}{}
	for _, c := range existingComponents {
		if cm, ok := c.(map[string]interface{}); ok {
			if id, _ := cm["Id"].(string); id != "" {
				componentMap[id] = cm
			}
		}
	}
	for _, id := range requiredComponents {
		componentMap[id] = map[string]interface{}{
			"Id":       id,
			"Severity": "LOGGER_SEVERITY_DEFAULT",
		}
	}
	var newComponents []interface{}
	for _, v := range componentMap {
		newComponents = append(newComponents, v)
	}
	loggingSection["LogComponents"] = newComponents
	settings["Logging"] = loggingSection

	newSettings, err := json.Marshal(settings)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "marshal updated settings: " + err.Error()
		return base
	}

	_, err = f.clients.DMS.ModifyReplicationTask(fctx.Ctx, &databasemigrationservice.ModifyReplicationTaskInput{
		ReplicationTaskArn:      aws.String(resourceID),
		ReplicationTaskSettings: aws.String(string(newSettings)),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "modify DMS replication task: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled logging for %v on DMS task %s", requiredComponents, resourceID)}
	base.Status = fix.FixApplied
	return base
}
