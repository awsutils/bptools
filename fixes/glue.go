package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
)

// ── glue-job-logging-enabled ──────────────────────────────────────────────────

type glueJobLoggingFix struct{ clients *awsdata.Clients }

func (f *glueJobLoggingFix) CheckID() string     { return "glue-job-logging-enabled" }
func (f *glueJobLoggingFix) Description() string { return "Enable CloudWatch logging on Glue job" }
func (f *glueJobLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *glueJobLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *glueJobLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.Glue.GetJob(fctx.Ctx, &glue.GetJobInput{
		JobName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get job: " + err.Error()
		return base
	}
	if out.Job == nil {
		base.Status = fix.FixFailed
		base.Message = "job not found: " + resourceID
		return base
	}
	j := out.Job

	// Idempotency check: if --enable-continuous-cloudwatch-log is not "false" or "0", logging is enabled
	if j.DefaultArguments != nil {
		val := j.DefaultArguments["--enable-continuous-cloudwatch-log"]
		if val != "false" && val != "0" && val != "" {
			base.Status = fix.FixSkipped
			base.Message = "CloudWatch logging already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable CloudWatch logging on Glue job " + resourceID}
		return base
	}

	// Build updated default arguments
	args := make(map[string]string)
	for k, v := range j.DefaultArguments {
		args[k] = v
	}
	args["--enable-continuous-cloudwatch-log"] = "true"

	// Build JobUpdate with required fields from current job
	update := &gluetypes.JobUpdate{
		Command:          j.Command,
		Role:             j.Role,
		DefaultArguments: args,
	}
	if j.Description != nil {
		update.Description = j.Description
	}
	if j.MaxCapacity != nil {
		update.MaxCapacity = j.MaxCapacity
	}
	if j.Timeout != nil {
		update.Timeout = j.Timeout
	}
	if j.MaxRetries != 0 {
		update.MaxRetries = j.MaxRetries
	}
	if j.GlueVersion != nil {
		update.GlueVersion = j.GlueVersion
	}
	if j.Connections != nil {
		update.Connections = j.Connections
	}
	if j.SecurityConfiguration != nil {
		update.SecurityConfiguration = j.SecurityConfiguration
	}
	if j.ExecutionClass != "" {
		update.ExecutionClass = j.ExecutionClass
	}
	if j.WorkerType != "" {
		update.WorkerType = j.WorkerType
	}
	if j.NumberOfWorkers != nil {
		update.NumberOfWorkers = j.NumberOfWorkers
	}
	if j.ExecutionProperty != nil {
		update.ExecutionProperty = j.ExecutionProperty
	}
	if j.NotificationProperty != nil {
		update.NotificationProperty = j.NotificationProperty
	}

	_, err = f.clients.Glue.UpdateJob(fctx.Ctx, &glue.UpdateJobInput{
		JobName:   aws.String(resourceID),
		JobUpdate: update,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update job: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled CloudWatch logging on Glue job " + resourceID}
	base.Status = fix.FixApplied
	return base
}
