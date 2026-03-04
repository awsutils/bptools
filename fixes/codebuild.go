package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
)

// ── codebuild-project-artifact-encryption ────────────────────────────────────

type codeBuildArtifactEncryptionFix struct{ clients *awsdata.Clients }

func (f *codeBuildArtifactEncryptionFix) CheckID() string {
	return "codebuild-project-artifact-encryption"
}
func (f *codeBuildArtifactEncryptionFix) Description() string {
	return "Enable artifact encryption on CodeBuild project"
}
func (f *codeBuildArtifactEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeBuildArtifactEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *codeBuildArtifactEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CodeBuild.BatchGetProjects(fctx.Ctx, &codebuild.BatchGetProjectsInput{
		Names: []string{resourceID},
	})
	if err != nil || len(out.Projects) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "batch get projects: " + err.Error()
		} else {
			base.Message = "project not found: " + resourceID
		}
		return base
	}
	p := out.Projects[0]

	// Idempotency check
	needsFix := false
	if p.Artifacts != nil && p.Artifacts.EncryptionDisabled != nil && *p.Artifacts.EncryptionDisabled {
		needsFix = true
	}
	for _, art := range p.SecondaryArtifacts {
		if art.EncryptionDisabled != nil && *art.EncryptionDisabled {
			needsFix = true
			break
		}
	}
	if !needsFix {
		base.Status = fix.FixSkipped
		base.Message = "artifact encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable artifact encryption on CodeBuild project " + resourceID}
		return base
	}

	// Build updated artifacts with encryption enabled
	var updatedArtifacts *cbtypes.ProjectArtifacts
	if p.Artifacts != nil {
		art := *p.Artifacts
		art.EncryptionDisabled = aws.Bool(false)
		updatedArtifacts = &art
	}
	updatedSecondary := make([]cbtypes.ProjectArtifacts, len(p.SecondaryArtifacts))
	for i, art := range p.SecondaryArtifacts {
		a := art
		a.EncryptionDisabled = aws.Bool(false)
		updatedSecondary[i] = a
	}

	_, err = f.clients.CodeBuild.UpdateProject(fctx.Ctx, &codebuild.UpdateProjectInput{
		Name:               aws.String(resourceID),
		Artifacts:          updatedArtifacts,
		SecondaryArtifacts: updatedSecondary,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update project: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled artifact encryption on CodeBuild project " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── codebuild-project-s3-logs-encrypted ──────────────────────────────────────

type codeBuildS3LogsEncryptionFix struct{ clients *awsdata.Clients }

func (f *codeBuildS3LogsEncryptionFix) CheckID() string {
	return "codebuild-project-s3-logs-encrypted"
}
func (f *codeBuildS3LogsEncryptionFix) Description() string {
	return "Enable S3 log encryption on CodeBuild project"
}
func (f *codeBuildS3LogsEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeBuildS3LogsEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *codeBuildS3LogsEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CodeBuild.BatchGetProjects(fctx.Ctx, &codebuild.BatchGetProjectsInput{
		Names: []string{resourceID},
	})
	if err != nil || len(out.Projects) == 0 {
		base.Status = fix.FixFailed
		if err != nil {
			base.Message = "batch get projects: " + err.Error()
		} else {
			base.Message = "project not found: " + resourceID
		}
		return base
	}
	p := out.Projects[0]

	// Only fix if S3 logs are configured and encryption is disabled
	if p.LogsConfig == nil || p.LogsConfig.S3Logs == nil || p.LogsConfig.S3Logs.Status == cbtypes.LogsConfigStatusTypeDisabled {
		base.Status = fix.FixSkipped
		base.Message = "S3 logs not configured"
		return base
	}
	if p.LogsConfig.S3Logs.EncryptionDisabled == nil || !*p.LogsConfig.S3Logs.EncryptionDisabled {
		base.Status = fix.FixSkipped
		base.Message = "S3 log encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable S3 log encryption on CodeBuild project " + resourceID}
		return base
	}

	s3Logs := *p.LogsConfig.S3Logs
	s3Logs.EncryptionDisabled = aws.Bool(false)
	_, err = f.clients.CodeBuild.UpdateProject(fctx.Ctx, &codebuild.UpdateProjectInput{
		Name: aws.String(resourceID),
		LogsConfig: &cbtypes.LogsConfig{
			S3Logs:         &s3Logs,
			CloudWatchLogs: p.LogsConfig.CloudWatchLogs,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update project: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled S3 log encryption on CodeBuild project " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── codebuild-project-logging-enabled ────────────────────────────────────────

type codeBuildProjectLoggingFix struct{ clients *awsdata.Clients }

func (f *codeBuildProjectLoggingFix) CheckID() string {
	return "codebuild-project-logging-enabled"
}
func (f *codeBuildProjectLoggingFix) Description() string {
	return "Enable CloudWatch Logs on CodeBuild project"
}
func (f *codeBuildProjectLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeBuildProjectLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *codeBuildProjectLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CodeBuild.BatchGetProjects(fctx.Ctx, &codebuild.BatchGetProjectsInput{
		Names: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get CodeBuild project: " + err.Error()
		return base
	}
	if len(out.Projects) == 0 {
		base.Status = fix.FixFailed
		base.Message = "CodeBuild project not found"
		return base
	}
	p := out.Projects[0]
	if p.LogsConfig != nil {
		if (p.LogsConfig.CloudWatchLogs != nil && p.LogsConfig.CloudWatchLogs.Status == cbtypes.LogsConfigStatusTypeEnabled) ||
			(p.LogsConfig.S3Logs != nil && p.LogsConfig.S3Logs.Status == cbtypes.LogsConfigStatusTypeEnabled) {
			base.Status = fix.FixSkipped
			base.Message = "logging already enabled"
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable CloudWatch Logs on CodeBuild project " + resourceID}
		return base
	}

	logsConfig := &cbtypes.LogsConfig{
		CloudWatchLogs: &cbtypes.CloudWatchLogsConfig{
			Status: cbtypes.LogsConfigStatusTypeEnabled,
		},
	}
	if p.LogsConfig != nil && p.LogsConfig.S3Logs != nil {
		logsConfig.S3Logs = p.LogsConfig.S3Logs
	}

	_, err = f.clients.CodeBuild.UpdateProject(fctx.Ctx, &codebuild.UpdateProjectInput{
		Name:       aws.String(resourceID),
		LogsConfig: logsConfig,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update project: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled CloudWatch Logs on CodeBuild project " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── codebuild-report-group-encrypted-at-rest ──────────────────────────────────

type codeBuildReportGroupEncryptionFix struct{ clients *awsdata.Clients }

func (f *codeBuildReportGroupEncryptionFix) CheckID() string {
	return "codebuild-report-group-encrypted-at-rest"
}
func (f *codeBuildReportGroupEncryptionFix) Description() string {
	return "Enable encryption on CodeBuild report group S3 export"
}
func (f *codeBuildReportGroupEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *codeBuildReportGroupEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *codeBuildReportGroupEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.CodeBuild.BatchGetReportGroups(fctx.Ctx, &codebuild.BatchGetReportGroupsInput{
		ReportGroupArns: []string{resourceID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "batch get report groups: " + err.Error()
		return base
	}
	if len(out.ReportGroups) == 0 {
		base.Status = fix.FixFailed
		base.Message = "report group not found"
		return base
	}
	rg := out.ReportGroups[0]

	if rg.ExportConfig == nil || rg.ExportConfig.S3Destination == nil {
		base.Status = fix.FixSkipped
		base.Message = "report group has no S3 export config"
		return base
	}
	if rg.ExportConfig.S3Destination.EncryptionDisabled == nil || !*rg.ExportConfig.S3Destination.EncryptionDisabled {
		base.Status = fix.FixSkipped
		base.Message = "report group S3 export encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable encryption on CodeBuild report group " + resourceID}
		return base
	}

	exportConfig := &cbtypes.ReportExportConfig{
		ExportConfigType: rg.ExportConfig.ExportConfigType,
		S3Destination: &cbtypes.S3ReportExportConfig{
			Bucket:            rg.ExportConfig.S3Destination.Bucket,
			BucketOwner:       rg.ExportConfig.S3Destination.BucketOwner,
			EncryptionDisabled: aws.Bool(false),
			EncryptionKey:     rg.ExportConfig.S3Destination.EncryptionKey,
			Packaging:         rg.ExportConfig.S3Destination.Packaging,
			Path:              rg.ExportConfig.S3Destination.Path,
		},
	}

	_, err = f.clients.CodeBuild.UpdateReportGroup(fctx.Ctx, &codebuild.UpdateReportGroupInput{
		Arn:          aws.String(resourceID),
		ExportConfig: exportConfig,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update report group: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled encryption on CodeBuild report group " + resourceID}
	base.Status = fix.FixApplied
	return base
}
