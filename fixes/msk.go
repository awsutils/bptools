package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
)

// ── msk-enhanced-monitoring-enabled ──────────────────────────────────────────

type mskEnhancedMonitoringFix struct{ clients *awsdata.Clients }

func (f *mskEnhancedMonitoringFix) CheckID() string {
	return "msk-enhanced-monitoring-enabled"
}
func (f *mskEnhancedMonitoringFix) Description() string {
	return "Enable enhanced monitoring (PER_TOPIC_PER_BROKER) on MSK cluster"
}
func (f *mskEnhancedMonitoringFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *mskEnhancedMonitoringFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *mskEnhancedMonitoringFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Kafka.DescribeClusterV2(fctx.Ctx, &kafka.DescribeClusterV2Input{
		ClusterArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe MSK cluster: " + err.Error()
		return base
	}
	if out.ClusterInfo == nil {
		base.Status = fix.FixFailed
		base.Message = "MSK cluster not found"
		return base
	}
	cl := out.ClusterInfo
	if cl.Provisioned != nil &&
		(cl.Provisioned.EnhancedMonitoring == kafkatypes.EnhancedMonitoringPerTopicPerBroker ||
			cl.Provisioned.EnhancedMonitoring == kafkatypes.EnhancedMonitoringPerTopicPerPartition) {
		base.Status = fix.FixSkipped
		base.Message = "enhanced monitoring already enabled"
		return base
	}
	if cl.Provisioned == nil {
		base.Status = fix.FixSkipped
		base.Message = "cluster is serverless; enhanced monitoring not applicable"
		return base
	}

	currentVersion := ""
	if cl.CurrentVersion != nil {
		currentVersion = *cl.CurrentVersion
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable PER_TOPIC_PER_BROKER monitoring on MSK cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Kafka.UpdateMonitoring(fctx.Ctx, &kafka.UpdateMonitoringInput{
		ClusterArn:         aws.String(resourceID),
		CurrentVersion:     aws.String(currentVersion),
		EnhancedMonitoring: kafkatypes.EnhancedMonitoringPerTopicPerBroker,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update MSK monitoring: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled PER_TOPIC_PER_BROKER monitoring on MSK cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── msk-cluster-public-access-disabled ───────────────────────────────────────

type mskPublicAccessFix struct{ clients *awsdata.Clients }

func (f *mskPublicAccessFix) CheckID() string { return "msk-cluster-public-access-disabled" }
func (f *mskPublicAccessFix) Description() string {
	return "Disable public access on MSK cluster brokers"
}
func (f *mskPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *mskPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *mskPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Kafka.DescribeClusterV2(fctx.Ctx, &kafka.DescribeClusterV2Input{
		ClusterArn: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe MSK cluster: " + err.Error()
		return base
	}
	if out.ClusterInfo == nil {
		base.Status = fix.FixFailed
		base.Message = "MSK cluster not found"
		return base
	}
	cl := out.ClusterInfo
	if cl.Provisioned == nil {
		base.Status = fix.FixSkipped
		base.Message = "cluster is serverless; public access setting not applicable"
		return base
	}
	if cl.Provisioned.BrokerNodeGroupInfo != nil &&
		cl.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo != nil &&
		cl.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess != nil &&
		cl.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type != nil &&
		*cl.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type == "DISABLED" {
		base.Status = fix.FixSkipped
		base.Message = "public access already disabled"
		return base
	}

	currentVersion := ""
	if cl.CurrentVersion != nil {
		currentVersion = *cl.CurrentVersion
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would disable public access on MSK cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.Kafka.UpdateConnectivity(fctx.Ctx, &kafka.UpdateConnectivityInput{
		ClusterArn:     aws.String(resourceID),
		CurrentVersion: aws.String(currentVersion),
		ConnectivityInfo: &kafkatypes.ConnectivityInfo{
			PublicAccess: &kafkatypes.PublicAccess{
				Type: aws.String("DISABLED"),
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update MSK connectivity: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("disabled public broker access on MSK cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
