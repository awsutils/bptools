package fixes

import (
	"os"
	"strconv"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
)

func registerMultiBatch02(d *awsdata.Data) {
	fix.Register(&batchComputeEnvironmentEnabledFix{clients: d.Clients})
	fix.Register(&batchComputeEnvironmentManagedFix{clients: d.Clients})
	fix.Register(&batchJobQueueEnabledFix{clients: d.Clients})
	fix.Register(&batchManagedComputeEnvironmentUsingLaunchTemplateFix{clients: d.Clients})
	fix.Register(&batchManagedComputeEnvironmentAllocationStrategyFix{clients: d.Clients})
	fix.Register(&batchManagedSpotComputeEnvironmentMaxBidFix{clients: d.Clients})
	fix.Register(&workspacesRootVolumeEncryptionEnabledFix{clients: d.Clients})
	fix.Register(&workspacesUserVolumeEncryptionEnabledFix{clients: d.Clients})
	fix.Register(&secretsManagerRotationEnabledFix{clients: d.Clients})
	fix.Register(&secretsManagerSecretPeriodicRotationFix{clients: d.Clients})
}

type batchComputeEnvironmentEnabledFix struct{ clients *awsdata.Clients }

func (f *batchComputeEnvironmentEnabledFix) CheckID() string {
	return "batch-compute-environment-enabled"
}
func (f *batchComputeEnvironmentEnabledFix) Description() string {
	return "Enable AWS Batch compute environment"
}
func (f *batchComputeEnvironmentEnabledFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *batchComputeEnvironmentEnabledFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *batchComputeEnvironmentEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	env, err := f.describeComputeEnvironment(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if env.State == batchtypes.CEStateEnabled {
		base.Status = fix.FixSkipped
		base.Message = "compute environment already enabled"
		return base
	}

	target := aws.ToString(env.ComputeEnvironmentName)
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable Batch compute environment " + target}
		return base
	}
	_, err = f.clients.Batch.UpdateComputeEnvironment(fctx.Ctx, &batch.UpdateComputeEnvironmentInput{
		ComputeEnvironment: env.ComputeEnvironmentName,
		State:              batchtypes.CEStateEnabled,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update compute environment: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"enabled Batch compute environment " + target}
	return base
}

type batchComputeEnvironmentManagedFix struct{ clients *awsdata.Clients }

func (f *batchComputeEnvironmentManagedFix) CheckID() string {
	return "batch-compute-environment-managed"
}
func (f *batchComputeEnvironmentManagedFix) Description() string {
	return "Use managed AWS Batch compute environment"
}
func (f *batchComputeEnvironmentManagedFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *batchComputeEnvironmentManagedFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *batchComputeEnvironmentManagedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	env, err := f.describeComputeEnvironment(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if env.Type == batchtypes.CETypeManaged {
		base.Status = fix.FixSkipped
		base.Message = "compute environment already managed"
		return base
	}

	base.Status = fix.FixSkipped
	base.Message = "AWS Batch does not support safe in-place conversion from UNMANAGED to MANAGED; recreate as managed"
	return base
}

type batchJobQueueEnabledFix struct{ clients *awsdata.Clients }

func (f *batchJobQueueEnabledFix) CheckID() string { return "batch-job-queue-enabled" }
func (f *batchJobQueueEnabledFix) Description() string {
	return "Enable AWS Batch job queue"
}
func (f *batchJobQueueEnabledFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *batchJobQueueEnabledFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *batchJobQueueEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	queue, err := f.describeJobQueue(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if queue.State == batchtypes.JQStateEnabled {
		base.Status = fix.FixSkipped
		base.Message = "job queue already enabled"
		return base
	}

	target := aws.ToString(queue.JobQueueName)
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable Batch job queue " + target}
		return base
	}
	_, err = f.clients.Batch.UpdateJobQueue(fctx.Ctx, &batch.UpdateJobQueueInput{
		JobQueue: queue.JobQueueName,
		State:    batchtypes.JQStateEnabled,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update job queue: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"enabled Batch job queue " + target}
	return base
}

type batchManagedComputeEnvironmentUsingLaunchTemplateFix struct{ clients *awsdata.Clients }

func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) CheckID() string {
	return "batch-managed-compute-environment-using-launch-template"
}
func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) Description() string {
	return "Configure launch template for managed AWS Batch compute environment"
}
func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	env, err := f.describeComputeEnvironment(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if env.Type != batchtypes.CETypeManaged || env.ComputeResources == nil {
		base.Status = fix.FixSkipped
		base.Message = "not a managed compute environment"
		return base
	}
	if batchHasLaunchTemplate(env.ComputeResources.LaunchTemplate) {
		base.Status = fix.FixSkipped
		base.Message = "launch template already configured"
		return base
	}

	ltID := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_LAUNCH_TEMPLATE_ID"))
	ltName := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_LAUNCH_TEMPLATE_NAME"))
	ltVersion := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_LAUNCH_TEMPLATE_VERSION"))
	if ltVersion == "" {
		ltVersion = "$Default"
	}
	if ltID == "" && ltName == "" {
		base.Status = fix.FixSkipped
		base.Message = "set BPTOOLS_BATCH_LAUNCH_TEMPLATE_ID or BPTOOLS_BATCH_LAUNCH_TEMPLATE_NAME to safely auto-fix"
		return base
	}
	if ltID != "" && ltName != "" {
		base.Status = fix.FixFailed
		base.Message = "only one of BPTOOLS_BATCH_LAUNCH_TEMPLATE_ID or BPTOOLS_BATCH_LAUNCH_TEMPLATE_NAME may be set"
		return base
	}

	target := aws.ToString(env.ComputeEnvironmentName)
	step := "would set launch template on Batch compute environment " + target
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{step}
		return base
	}
	ltSpec := &batchtypes.LaunchTemplateSpecification{Version: aws.String(ltVersion)}
	if ltID != "" {
		ltSpec.LaunchTemplateId = aws.String(ltID)
	}
	if ltName != "" {
		ltSpec.LaunchTemplateName = aws.String(ltName)
	}
	_, err = f.clients.Batch.UpdateComputeEnvironment(fctx.Ctx, &batch.UpdateComputeEnvironmentInput{
		ComputeEnvironment: env.ComputeEnvironmentName,
		ComputeResources: &batchtypes.ComputeResourceUpdate{
			LaunchTemplate: ltSpec,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update compute environment launch template: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set launch template on Batch compute environment " + target}
	return base
}

type batchManagedComputeEnvironmentAllocationStrategyFix struct{ clients *awsdata.Clients }

func (f *batchManagedComputeEnvironmentAllocationStrategyFix) CheckID() string {
	return "batch-managed-compute-env-allocation-strategy-check"
}
func (f *batchManagedComputeEnvironmentAllocationStrategyFix) Description() string {
	return "Set allowed allocation strategy for managed AWS Batch compute environment"
}
func (f *batchManagedComputeEnvironmentAllocationStrategyFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *batchManagedComputeEnvironmentAllocationStrategyFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *batchManagedComputeEnvironmentAllocationStrategyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	env, err := f.describeComputeEnvironment(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if env.Type != batchtypes.CETypeManaged || env.ComputeResources == nil {
		base.Status = fix.FixSkipped
		base.Message = "not a managed compute environment"
		return base
	}

	current := strings.ToUpper(strings.TrimSpace(string(env.ComputeResources.AllocationStrategy)))
	allowed := batchAllowedAllocationStrategiesFromEnv()
	if allowed[current] {
		base.Status = fix.FixSkipped
		base.Message = "allocation strategy already allowed"
		return base
	}

	target := batchPreferredAllocationStrategy(allowed, env.ComputeResources.Type)
	if target == "" {
		base.Status = fix.FixSkipped
		base.Message = "no allowed allocation strategy configured"
		return base
	}

	envName := aws.ToString(env.ComputeEnvironmentName)
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set allocation strategy to " + target + " for Batch compute environment " + envName}
		return base
	}
	_, err = f.clients.Batch.UpdateComputeEnvironment(fctx.Ctx, &batch.UpdateComputeEnvironmentInput{
		ComputeEnvironment: env.ComputeEnvironmentName,
		ComputeResources: &batchtypes.ComputeResourceUpdate{
			AllocationStrategy: batchtypes.CRUpdateAllocationStrategy(target),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update allocation strategy: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set allocation strategy to " + target + " for Batch compute environment " + envName}
	return base
}

type batchManagedSpotComputeEnvironmentMaxBidFix struct{ clients *awsdata.Clients }

func (f *batchManagedSpotComputeEnvironmentMaxBidFix) CheckID() string {
	return "batch-managed-spot-compute-environment-max-bid"
}
func (f *batchManagedSpotComputeEnvironmentMaxBidFix) Description() string {
	return "Set max bid percentage for AWS Batch managed Spot compute environment"
}
func (f *batchManagedSpotComputeEnvironmentMaxBidFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *batchManagedSpotComputeEnvironmentMaxBidFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *batchManagedSpotComputeEnvironmentMaxBidFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	env, err := f.describeComputeEnvironment(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if env.Type != batchtypes.CETypeManaged || env.ComputeResources == nil || env.ComputeResources.Type != batchtypes.CRTypeSpot {
		base.Status = fix.FixSkipped
		base.Message = "not a managed Spot compute environment"
		return base
	}

	maxBid := batchMaxBidPercentageFromEnv()
	currentBid := int32(0)
	if env.ComputeResources.BidPercentage != nil {
		currentBid = *env.ComputeResources.BidPercentage
	}
	if currentBid > 0 && currentBid <= maxBid {
		base.Status = fix.FixSkipped
		base.Message = "bid percentage already within allowed maximum"
		return base
	}

	envName := aws.ToString(env.ComputeEnvironmentName)
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set bid percentage to " + strconv.Itoa(int(maxBid)) + " for Batch compute environment " + envName}
		return base
	}
	_, err = f.clients.Batch.UpdateComputeEnvironment(fctx.Ctx, &batch.UpdateComputeEnvironmentInput{
		ComputeEnvironment: env.ComputeEnvironmentName,
		ComputeResources: &batchtypes.ComputeResourceUpdate{
			BidPercentage: aws.Int32(maxBid),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update Spot bid percentage: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"set bid percentage to " + strconv.Itoa(int(maxBid)) + " for Batch compute environment " + envName}
	return base
}

type workspacesRootVolumeEncryptionEnabledFix struct{ clients *awsdata.Clients }

func (f *workspacesRootVolumeEncryptionEnabledFix) CheckID() string {
	return "workspaces-root-volume-encryption-enabled"
}
func (f *workspacesRootVolumeEncryptionEnabledFix) Description() string {
	return "Enable WorkSpaces root volume encryption"
}
func (f *workspacesRootVolumeEncryptionEnabledFix) Impact() fix.ImpactType { return fix.ImpactDown }
func (f *workspacesRootVolumeEncryptionEnabledFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *workspacesRootVolumeEncryptionEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	ws, err := f.describeWorkspace(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if ws.RootVolumeEncryptionEnabled != nil && *ws.RootVolumeEncryptionEnabled {
		base.Status = fix.FixSkipped
		base.Message = "root volume encryption already enabled"
		return base
	}

	base.Status = fix.FixSkipped
	base.Message = "AWS WorkSpaces does not support enabling root volume encryption in-place; rebuild/migrate to an encrypted WorkSpace"
	return base
}

type workspacesUserVolumeEncryptionEnabledFix struct{ clients *awsdata.Clients }

func (f *workspacesUserVolumeEncryptionEnabledFix) CheckID() string {
	return "workspaces-user-volume-encryption-enabled"
}
func (f *workspacesUserVolumeEncryptionEnabledFix) Description() string {
	return "Enable WorkSpaces user volume encryption"
}
func (f *workspacesUserVolumeEncryptionEnabledFix) Impact() fix.ImpactType { return fix.ImpactDown }
func (f *workspacesUserVolumeEncryptionEnabledFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *workspacesUserVolumeEncryptionEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	ws, err := f.describeWorkspace(fctx, resourceID)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = err.Error()
		return base
	}
	if ws.UserVolumeEncryptionEnabled != nil && *ws.UserVolumeEncryptionEnabled {
		base.Status = fix.FixSkipped
		base.Message = "user volume encryption already enabled"
		return base
	}

	base.Status = fix.FixSkipped
	base.Message = "AWS WorkSpaces does not support enabling user volume encryption in-place; rebuild/migrate to an encrypted WorkSpace"
	return base
}

type secretsManagerRotationEnabledFix struct{ clients *awsdata.Clients }

func (f *secretsManagerRotationEnabledFix) CheckID() string {
	return "secretsmanager-rotation-enabled-check"
}
func (f *secretsManagerRotationEnabledFix) Description() string {
	return "Enable Secrets Manager rotation"
}
func (f *secretsManagerRotationEnabledFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *secretsManagerRotationEnabledFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *secretsManagerRotationEnabledFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	secretID := strings.TrimSpace(resourceID)
	if secretID == "" || secretID == "unknown" {
		base.Status = fix.FixFailed
		base.Message = "missing secret identifier"
		return base
	}

	desc, err := f.clients.SecretsManager.DescribeSecret(fctx.Ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(secretID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe secret: " + err.Error()
		return base
	}
	if desc.RotationEnabled != nil && *desc.RotationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "rotation already enabled"
		return base
	}
	if desc.DeletedDate != nil {
		base.Status = fix.FixSkipped
		base.Message = "secret is scheduled for deletion"
		return base
	}

	input, reason := buildRotateSecretInput(desc, secretID, false)
	if input == nil {
		base.Status = fix.FixSkipped
		base.Message = reason
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable rotation for secret " + secretID}
		return base
	}
	_, err = f.clients.SecretsManager.RotateSecret(fctx.Ctx, input)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "enable rotation: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"enabled rotation for secret " + secretID}
	return base
}

type secretsManagerSecretPeriodicRotationFix struct{ clients *awsdata.Clients }

func (f *secretsManagerSecretPeriodicRotationFix) CheckID() string {
	return "secretsmanager-secret-periodic-rotation"
}
func (f *secretsManagerSecretPeriodicRotationFix) Description() string {
	return "Trigger periodic rotation for Secrets Manager secret"
}
func (f *secretsManagerSecretPeriodicRotationFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *secretsManagerSecretPeriodicRotationFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *secretsManagerSecretPeriodicRotationFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	secretID := strings.TrimSpace(resourceID)
	if secretID == "" || secretID == "unknown" {
		base.Status = fix.FixFailed
		base.Message = "missing secret identifier"
		return base
	}

	desc, err := f.clients.SecretsManager.DescribeSecret(fctx.Ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(secretID)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe secret: " + err.Error()
		return base
	}
	if desc.DeletedDate != nil {
		base.Status = fix.FixSkipped
		base.Message = "secret is scheduled for deletion"
		return base
	}

	maxDays := secretPeriodicRotationDaysFromEnv()
	if desc.LastRotatedDate != nil && time.Since(*desc.LastRotatedDate) < time.Duration(maxDays)*24*time.Hour {
		base.Status = fix.FixSkipped
		base.Message = "secret rotated within allowed period"
		return base
	}

	input, reason := buildRotateSecretInput(desc, secretID, true)
	if input == nil {
		base.Status = fix.FixSkipped
		base.Message = reason
		return base
	}
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would trigger rotation for secret " + secretID}
		return base
	}
	_, err = f.clients.SecretsManager.RotateSecret(fctx.Ctx, input)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "rotate secret: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{"triggered rotation for secret " + secretID}
	return base
}

func (f *batchComputeEnvironmentEnabledFix) describeComputeEnvironment(fctx fix.FixContext, resourceID string) (*batchtypes.ComputeEnvironmentDetail, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" || id == "unknown" {
		return nil, errString("missing compute environment identifier")
	}
	out, err := f.clients.Batch.DescribeComputeEnvironments(fctx.Ctx, &batch.DescribeComputeEnvironmentsInput{
		ComputeEnvironments: []string{id},
	})
	if err != nil {
		return nil, errWrap("describe compute environment", err)
	}
	if len(out.ComputeEnvironments) == 0 {
		return nil, errString("compute environment not found")
	}
	return &out.ComputeEnvironments[0], nil
}

func (f *batchComputeEnvironmentManagedFix) describeComputeEnvironment(fctx fix.FixContext, resourceID string) (*batchtypes.ComputeEnvironmentDetail, error) {
	return (&batchComputeEnvironmentEnabledFix{clients: f.clients}).describeComputeEnvironment(fctx, resourceID)
}

func (f *batchManagedComputeEnvironmentUsingLaunchTemplateFix) describeComputeEnvironment(fctx fix.FixContext, resourceID string) (*batchtypes.ComputeEnvironmentDetail, error) {
	return (&batchComputeEnvironmentEnabledFix{clients: f.clients}).describeComputeEnvironment(fctx, resourceID)
}

func (f *batchManagedComputeEnvironmentAllocationStrategyFix) describeComputeEnvironment(fctx fix.FixContext, resourceID string) (*batchtypes.ComputeEnvironmentDetail, error) {
	return (&batchComputeEnvironmentEnabledFix{clients: f.clients}).describeComputeEnvironment(fctx, resourceID)
}

func (f *batchManagedSpotComputeEnvironmentMaxBidFix) describeComputeEnvironment(fctx fix.FixContext, resourceID string) (*batchtypes.ComputeEnvironmentDetail, error) {
	return (&batchComputeEnvironmentEnabledFix{clients: f.clients}).describeComputeEnvironment(fctx, resourceID)
}

func (f *batchJobQueueEnabledFix) describeJobQueue(fctx fix.FixContext, resourceID string) (*batchtypes.JobQueueDetail, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" || id == "unknown" {
		return nil, errString("missing job queue identifier")
	}
	out, err := f.clients.Batch.DescribeJobQueues(fctx.Ctx, &batch.DescribeJobQueuesInput{JobQueues: []string{id}})
	if err != nil {
		return nil, errWrap("describe job queue", err)
	}
	if len(out.JobQueues) == 0 {
		return nil, errString("job queue not found")
	}
	return &out.JobQueues[0], nil
}

func (f *workspacesRootVolumeEncryptionEnabledFix) describeWorkspace(fctx fix.FixContext, resourceID string) (*workspacestypes.Workspace, error) {
	id := strings.TrimSpace(resourceID)
	if id == "" || id == "unknown" {
		return nil, errString("missing WorkSpace ID")
	}
	out, err := f.clients.Workspaces.DescribeWorkspaces(fctx.Ctx, &workspaces.DescribeWorkspacesInput{WorkspaceIds: []string{id}})
	if err != nil {
		return nil, errWrap("describe WorkSpace", err)
	}
	if len(out.Workspaces) == 0 {
		return nil, errString("WorkSpace not found")
	}
	return &out.Workspaces[0], nil
}

func (f *workspacesUserVolumeEncryptionEnabledFix) describeWorkspace(fctx fix.FixContext, resourceID string) (*workspacestypes.Workspace, error) {
	return (&workspacesRootVolumeEncryptionEnabledFix{clients: f.clients}).describeWorkspace(fctx, resourceID)
}

func batchAllowedAllocationStrategiesFromEnv() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_ALLOWED_ALLOCATION_STRATEGIES"))
	values := []string{
		string(batchtypes.CRAllocationStrategyBestFitProgressive),
		string(batchtypes.CRAllocationStrategySpotCapacityOptimized),
		string(batchtypes.CRAllocationStrategySpotPriceCapacityOptimized),
	}
	if raw != "" {
		parts := strings.Split(raw, ",")
		values = make([]string, 0, len(parts))
		for _, part := range parts {
			item := strings.ToUpper(strings.TrimSpace(part))
			if item != "" {
				values = append(values, item)
			}
		}
	}
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[strings.ToUpper(strings.TrimSpace(v))] = true
	}
	return out
}

func batchPreferredAllocationStrategy(allowed map[string]bool, crType batchtypes.CRType) string {
	spotOrder := []string{
		string(batchtypes.CRAllocationStrategySpotPriceCapacityOptimized),
		string(batchtypes.CRAllocationStrategySpotCapacityOptimized),
		string(batchtypes.CRAllocationStrategyBestFitProgressive),
	}
	onDemandOrder := []string{
		string(batchtypes.CRAllocationStrategyBestFitProgressive),
		string(batchtypes.CRAllocationStrategySpotPriceCapacityOptimized),
		string(batchtypes.CRAllocationStrategySpotCapacityOptimized),
	}
	order := onDemandOrder
	if crType == batchtypes.CRTypeSpot {
		order = spotOrder
	}
	for _, v := range order {
		key := strings.ToUpper(strings.TrimSpace(v))
		if allowed[key] {
			return key
		}
	}
	return ""
}

func batchMaxBidPercentageFromEnv() int32 {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_BATCH_MAX_BID_PERCENTAGE"))
	if raw == "" {
		return 100
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 100
	}
	if value > 100 {
		return 100
	}
	return int32(value)
}

func batchHasLaunchTemplate(lt *batchtypes.LaunchTemplateSpecification) bool {
	if lt == nil {
		return false
	}
	return strings.TrimSpace(aws.ToString(lt.LaunchTemplateId)) != "" || strings.TrimSpace(aws.ToString(lt.LaunchTemplateName)) != ""
}

func secretRotationDaysFromEnv() int64 {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_SECRETSMANAGER_ROTATION_DAYS"))
	if raw == "" {
		return 30
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 30
	}
	if v > 1000 {
		v = 1000
	}
	return int64(v)
}

func secretPeriodicRotationDaysFromEnv() int {
	raw := strings.TrimSpace(os.Getenv("BPTOOLS_SECRETSMANAGER_MAX_DAYS_SINCE_ROTATION"))
	if raw == "" {
		return 90
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 90
	}
	if v > 3650 {
		v = 3650
	}
	return v
}

func buildRotateSecretInput(desc *secretsmanager.DescribeSecretOutput, secretID string, rotateImmediately bool) (*secretsmanager.RotateSecretInput, string) {
	if desc == nil {
		return nil, "secret description unavailable"
	}
	if desc.OwningService != nil && strings.TrimSpace(*desc.OwningService) != "" {
		return nil, "secret is managed by another AWS service"
	}
	if desc.RotationLambdaARN == nil || strings.TrimSpace(*desc.RotationLambdaARN) == "" {
		return nil, "rotation Lambda ARN is missing"
	}

	days := secretRotationDaysFromEnv()
	if desc.RotationRules != nil && desc.RotationRules.AutomaticallyAfterDays != nil && *desc.RotationRules.AutomaticallyAfterDays > 0 {
		days = *desc.RotationRules.AutomaticallyAfterDays
	}
	input := &secretsmanager.RotateSecretInput{
		SecretId:          aws.String(secretID),
		RotateImmediately: aws.Bool(rotateImmediately),
		RotationLambdaARN: desc.RotationLambdaARN,
		RotationRules:     &smtypes.RotationRulesType{AutomaticallyAfterDays: aws.Int64(days)},
	}
	return input, ""
}

type errString string

func (e errString) Error() string { return string(e) }

func errWrap(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return errString(prefix + ": " + err.Error())
}
