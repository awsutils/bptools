package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

// ── autoscaling-capacity-rebalancing ─────────────────────────────────────────

type autoscalingCapacityRebalancingFix struct{ clients *awsdata.Clients }

func (f *autoscalingCapacityRebalancingFix) CheckID() string {
	return "autoscaling-capacity-rebalancing"
}
func (f *autoscalingCapacityRebalancingFix) Description() string {
	return "Enable Capacity Rebalancing on Auto Scaling group"
}
func (f *autoscalingCapacityRebalancingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *autoscalingCapacityRebalancingFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *autoscalingCapacityRebalancingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.AutoScaling.DescribeAutoScalingGroups(fctx.Ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Auto Scaling group: " + err.Error()
		return base
	}
	if len(out.AutoScalingGroups) > 0 && out.AutoScalingGroups[0].CapacityRebalance != nil && *out.AutoScalingGroups[0].CapacityRebalance {
		base.Status = fix.FixSkipped
		base.Message = "capacity rebalancing already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable capacity rebalancing on Auto Scaling group %s", resourceID)}
		return base
	}

	_, err = f.clients.AutoScaling.UpdateAutoScalingGroup(fctx.Ctx, &autoscaling.UpdateAutoScalingGroupInput{
		AutoScalingGroupName: aws.String(resourceID),
		CapacityRebalance:    aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update Auto Scaling group: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled capacity rebalancing on Auto Scaling group %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── autoscaling-group-elb-healthcheck-required ───────────────────────────────

type autoscalingELBHealthCheckFix struct{ clients *awsdata.Clients }

func (f *autoscalingELBHealthCheckFix) CheckID() string {
	return "autoscaling-group-elb-healthcheck-required"
}
func (f *autoscalingELBHealthCheckFix) Description() string {
	return "Use ELB health checks on Auto Scaling group attached to a load balancer"
}
func (f *autoscalingELBHealthCheckFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *autoscalingELBHealthCheckFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *autoscalingELBHealthCheckFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.AutoScaling.DescribeAutoScalingGroups(fctx.Ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe Auto Scaling group: " + err.Error()
		return base
	}
	if len(out.AutoScalingGroups) == 0 {
		base.Status = fix.FixFailed
		base.Message = "Auto Scaling group not found"
		return base
	}
	g := out.AutoScalingGroups[0]
	attachedToLB := len(g.LoadBalancerNames) > 0 || len(g.TargetGroupARNs) > 0
	if !attachedToLB {
		base.Status = fix.FixSkipped
		base.Message = "Auto Scaling group has no load balancers; ELB health check not needed"
		return base
	}
	if g.HealthCheckType != nil && *g.HealthCheckType == "ELB" {
		base.Status = fix.FixSkipped
		base.Message = "ELB health check already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set HealthCheckType=ELB on Auto Scaling group %s", resourceID)}
		return base
	}

	_, err = f.clients.AutoScaling.UpdateAutoScalingGroup(fctx.Ctx, &autoscaling.UpdateAutoScalingGroupInput{
		AutoScalingGroupName: aws.String(resourceID),
		HealthCheckType:      aws.String("ELB"),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update Auto Scaling group: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("set HealthCheckType=ELB on Auto Scaling group %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
