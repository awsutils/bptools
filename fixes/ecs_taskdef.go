package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ecsRegisterTaskDefRevision creates a new task definition revision based on an
// existing one, applying the supplied mutator to each container definition.
func ecsRegisterTaskDefRevision(
	fctx fix.FixContext,
	clients *awsdata.Clients,
	taskDefArn string,
	mutateFn func(c *ecstypes.ContainerDefinition),
) (string, error) {
	out, err := clients.ECS.DescribeTaskDefinition(fctx.Ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefArn),
	})
	if err != nil {
		return "", fmt.Errorf("describe task definition: %w", err)
	}
	td := out.TaskDefinition
	if td == nil {
		return "", fmt.Errorf("task definition not found")
	}

	// Copy and mutate container definitions
	newContainers := make([]ecstypes.ContainerDefinition, len(td.ContainerDefinitions))
	for i, c := range td.ContainerDefinitions {
		cp := c
		mutateFn(&cp)
		newContainers[i] = cp
	}

	input := &ecs.RegisterTaskDefinitionInput{
		Family:                  td.Family,
		ContainerDefinitions:    newContainers,
		NetworkMode:             td.NetworkMode,
		TaskRoleArn:             td.TaskRoleArn,
		ExecutionRoleArn:        td.ExecutionRoleArn,
		Volumes:                 td.Volumes,
		PlacementConstraints:    td.PlacementConstraints,
		RequiresCompatibilities: td.RequiresCompatibilities,
		Cpu:                     td.Cpu,
		Memory:                  td.Memory,
		EphemeralStorage:        td.EphemeralStorage,
		InferenceAccelerators:   td.InferenceAccelerators,
		IpcMode:                 td.IpcMode,
		PidMode:                 td.PidMode,
		RuntimePlatform:         td.RuntimePlatform,
		ProxyConfiguration:      td.ProxyConfiguration,
	}

	reg, err := clients.ECS.RegisterTaskDefinition(fctx.Ctx, input)
	if err != nil {
		return "", fmt.Errorf("register task definition: %w", err)
	}
	if reg.TaskDefinition == nil || reg.TaskDefinition.TaskDefinitionArn == nil {
		return "", fmt.Errorf("registered task definition has no ARN")
	}
	return *reg.TaskDefinition.TaskDefinitionArn, nil
}

// ── ecs-containers-nonprivileged ─────────────────────────────────────────────

type ecsContainersNonprivilegedFix struct{ clients *awsdata.Clients }

func (f *ecsContainersNonprivilegedFix) CheckID() string {
	return "ecs-containers-nonprivileged"
}
func (f *ecsContainersNonprivilegedFix) Description() string {
	return "Set privileged=false on all containers in ECS task definition"
}
func (f *ecsContainersNonprivilegedFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecsContainersNonprivilegedFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *ecsContainersNonprivilegedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ECS.DescribeTaskDefinition(fctx.Ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe task definition: " + err.Error()
		return base
	}
	if out.TaskDefinition == nil {
		base.Status = fix.FixFailed
		base.Message = "task definition not found"
		return base
	}

	needsFix := false
	for _, c := range out.TaskDefinition.ContainerDefinitions {
		if c.Privileged != nil && *c.Privileged {
			needsFix = true
			break
		}
	}
	if !needsFix {
		base.Status = fix.FixSkipped
		base.Message = "no privileged containers found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would register new task definition revision with privileged=false for %s", resourceID)}
		return base
	}

	newArn, err := ecsRegisterTaskDefRevision(fctx, f.clients, resourceID, func(c *ecstypes.ContainerDefinition) {
		c.Privileged = aws.Bool(false)
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("registered new task definition revision %s with privileged=false", newArn)}
	base.Status = fix.FixApplied
	return base
}

// ── ecs-containers-readonly-access ───────────────────────────────────────────

type ecsContainersReadOnlyFix struct{ clients *awsdata.Clients }

func (f *ecsContainersReadOnlyFix) CheckID() string {
	return "ecs-containers-readonly-access"
}
func (f *ecsContainersReadOnlyFix) Description() string {
	return "Set readonlyRootFilesystem=true on all containers in ECS task definition"
}
func (f *ecsContainersReadOnlyFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *ecsContainersReadOnlyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *ecsContainersReadOnlyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.ECS.DescribeTaskDefinition(fctx.Ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe task definition: " + err.Error()
		return base
	}
	if out.TaskDefinition == nil {
		base.Status = fix.FixFailed
		base.Message = "task definition not found"
		return base
	}

	needsFix := false
	for _, c := range out.TaskDefinition.ContainerDefinitions {
		if c.ReadonlyRootFilesystem == nil || !*c.ReadonlyRootFilesystem {
			needsFix = true
			break
		}
	}
	if !needsFix {
		base.Status = fix.FixSkipped
		base.Message = "all containers already have read-only root filesystem"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would register new task definition revision with readonlyRootFilesystem=true for %s", resourceID)}
		return base
	}

	newArn, err := ecsRegisterTaskDefRevision(fctx, f.clients, resourceID, func(c *ecstypes.ContainerDefinition) {
		c.ReadonlyRootFilesystem = aws.Bool(true)
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("registered new task definition revision %s with readonlyRootFilesystem=true", newArn)}
	base.Status = fix.FixApplied
	return base
}
