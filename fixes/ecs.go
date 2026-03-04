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

// ── ecs-fargate-latest-platform-version ──────────────────────────────────────

type ecsFargatePlatformVersionFix struct{ clients *awsdata.Clients }

func (f *ecsFargatePlatformVersionFix) CheckID() string {
	return "ecs-fargate-latest-platform-version"
}
func (f *ecsFargatePlatformVersionFix) Description() string {
	return "Set ECS Fargate service platform version to LATEST"
}
func (f *ecsFargatePlatformVersionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecsFargatePlatformVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *ecsFargatePlatformVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Extract cluster from service ARN: arn:aws:ecs:region:account:service/cluster/service-name
	var clusterName string
	parts := strings.SplitN(resourceID, ":", 6)
	if len(parts) == 6 {
		// parts[5] = "service/cluster-name/service-name"
		pathParts := strings.Split(parts[5], "/")
		if len(pathParts) >= 2 {
			clusterName = pathParts[1]
		}
	}

	svcOut, err := f.clients.ECS.DescribeServices(fctx.Ctx, &ecs.DescribeServicesInput{
		Cluster:  aws.String(clusterName),
		Services: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe services: " + err.Error()
		return base
	}
	if len(svcOut.Services) == 0 {
		base.Status = fix.FixFailed
		base.Message = "service not found"
		return base
	}
	svc := svcOut.Services[0]

	if svc.LaunchType != ecstypes.LaunchTypeFargate {
		base.Status = fix.FixSkipped
		base.Message = "service is not a Fargate service"
		return base
	}
	if svc.PlatformVersion != nil && strings.ToUpper(*svc.PlatformVersion) == "LATEST" {
		base.Status = fix.FixSkipped
		base.Message = "platform version already set to LATEST"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set platform version to LATEST on ECS Fargate service %s", resourceID)}
		return base
	}

	_, err = f.clients.ECS.UpdateService(fctx.Ctx, &ecs.UpdateServiceInput{
		Cluster:         aws.String(clusterName),
		Service:         aws.String(resourceID),
		PlatformVersion: aws.String("LATEST"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update service: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set platform version to LATEST on ECS Fargate service %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
