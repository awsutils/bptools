package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

// ── global-endpoint-event-replication-enabled ────────────────────────────────

type globalEndpointReplicationFix struct{ clients *awsdata.Clients }

func (f *globalEndpointReplicationFix) CheckID() string {
	return "global-endpoint-event-replication-enabled"
}
func (f *globalEndpointReplicationFix) Description() string {
	return "Enable event replication on EventBridge global endpoint"
}
func (f *globalEndpointReplicationFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *globalEndpointReplicationFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *globalEndpointReplicationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.EventBridge.DescribeEndpoint(fctx.Ctx, &eventbridge.DescribeEndpointInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe endpoint: " + err.Error()
		return base
	}
	if out.ReplicationConfig != nil && out.ReplicationConfig.State == eventbridgetypes.ReplicationStateEnabled {
		base.Status = fix.FixSkipped
		base.Message = "event replication already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable event replication on EventBridge global endpoint %s", resourceID)}
		return base
	}

	_, err = f.clients.EventBridge.UpdateEndpoint(fctx.Ctx, &eventbridge.UpdateEndpointInput{
		Name: aws.String(resourceID),
		ReplicationConfig: &eventbridgetypes.ReplicationConfig{
			State: eventbridgetypes.ReplicationStateEnabled,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update endpoint: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled event replication on EventBridge global endpoint %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
