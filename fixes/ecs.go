package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ── ecs-container-insights-enabled ───────────────────────────────────────────

type ecsContainerInsightsFix struct{ clients *awsdata.Clients }

func (f *ecsContainerInsightsFix) CheckID() string          { return "ecs-container-insights-enabled" }
func (f *ecsContainerInsightsFix) Description() string      { return "Enable ECS cluster Container Insights" }
func (f *ecsContainerInsightsFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *ecsContainerInsightsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ecsContainerInsightsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ECS.DescribeClusters(fctx.Ctx, &ecs.DescribeClustersInput{
		Clusters: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe cluster: " + err.Error()
		return base
	}
	if len(out.Clusters) == 0 {
		base.Status = fix.FixFailed
		base.Message = "cluster not found"
		return base
	}
	for _, s := range out.Clusters[0].Settings {
		if s.Name == ecstypes.ClusterSettingNameContainerInsights && s.Value != nil && strings.EqualFold(*s.Value, "enabled") {
			base.Status = fix.FixSkipped
			base.Message = "container insights already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable container insights on ECS cluster %s", resourceID)}
		return base
	}

	_, err = f.clients.ECS.UpdateCluster(fctx.Ctx, &ecs.UpdateClusterInput{
		Cluster: aws.String(resourceID),
		Settings: []ecstypes.ClusterSetting{
			{Name: ecstypes.ClusterSettingNameContainerInsights, Value: aws.String("enabled")},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update cluster: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled container insights on ECS cluster %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
