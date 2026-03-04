package fixes

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
)

// fsxFileSystemID extracts the FileSystemId from a resource ID that may be
// either a raw ID (fs-xxxxx) or an ARN (arn:aws:fsx:...:file-system/fs-xxxxx).
func fsxFileSystemID(resourceID string) string {
	if strings.HasPrefix(resourceID, "arn:") {
		// ARN format: arn:aws:fsx:region:account:file-system/fs-xxxxx
		parts := strings.SplitN(resourceID, "/", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return resourceID
}

// ── fsx-openzfs-copy-tags-enabled ─────────────────────────────────────────────

type fsxOpenZFSCopyTagsFix struct{ clients *awsdata.Clients }

func (f *fsxOpenZFSCopyTagsFix) CheckID() string { return "fsx-openzfs-copy-tags-enabled" }
func (f *fsxOpenZFSCopyTagsFix) Description() string {
	return "Enable CopyTagsToBackups and CopyTagsToVolumes on FSx for OpenZFS file system"
}
func (f *fsxOpenZFSCopyTagsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *fsxOpenZFSCopyTagsFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *fsxOpenZFSCopyTagsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	fsID := fsxFileSystemID(resourceID)
	out, err := f.clients.FSx.DescribeFileSystems(fctx.Ctx, &fsx.DescribeFileSystemsInput{
		FileSystemIds: []string{fsID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe file system: " + err.Error()
		return base
	}
	if len(out.FileSystems) == 0 {
		base.Status = fix.FixFailed
		base.Message = "file system not found"
		return base
	}
	fs := out.FileSystems[0]
	if fs.FileSystemType != fsxtypes.FileSystemTypeOpenzfs {
		base.Status = fix.FixSkipped
		base.Message = "not an OpenZFS file system"
		return base
	}
	cfg := fs.OpenZFSConfiguration
	alreadyOK := cfg != nil &&
		cfg.CopyTagsToBackups != nil && *cfg.CopyTagsToBackups &&
		cfg.CopyTagsToVolumes != nil && *cfg.CopyTagsToVolumes
	if alreadyOK {
		base.Status = fix.FixSkipped
		base.Message = "CopyTagsToBackups and CopyTagsToVolumes already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable CopyTagsToBackups and CopyTagsToVolumes on FSx OpenZFS file system %s", fsID)}
		return base
	}

	_, err = f.clients.FSx.UpdateFileSystem(fctx.Ctx, &fsx.UpdateFileSystemInput{
		FileSystemId: aws.String(fsID),
		OpenZFSConfiguration: &fsxtypes.UpdateFileSystemOpenZFSConfiguration{
			CopyTagsToBackups: aws.Bool(true),
			CopyTagsToVolumes: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update file system: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled CopyTagsToBackups and CopyTagsToVolumes on FSx OpenZFS file system %s", fsID)}
	base.Status = fix.FixApplied
	return base
}

// ── fsx-windows-audit-log-configured ─────────────────────────────────────────

type fsxWindowsAuditLogFix struct{ clients *awsdata.Clients }

func (f *fsxWindowsAuditLogFix) CheckID() string { return "fsx-windows-audit-log-configured" }
func (f *fsxWindowsAuditLogFix) Description() string {
	return "Enable file access auditing on FSx for Windows file system"
}
func (f *fsxWindowsAuditLogFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *fsxWindowsAuditLogFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *fsxWindowsAuditLogFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	fsID := fsxFileSystemID(resourceID)
	out, err := f.clients.FSx.DescribeFileSystems(fctx.Ctx, &fsx.DescribeFileSystemsInput{
		FileSystemIds: []string{fsID},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe file system: " + err.Error()
		return base
	}
	if len(out.FileSystems) == 0 {
		base.Status = fix.FixFailed
		base.Message = "file system not found"
		return base
	}
	fs := out.FileSystems[0]
	if fs.FileSystemType != fsxtypes.FileSystemTypeWindows {
		base.Status = fix.FixSkipped
		base.Message = "not a Windows file system"
		return base
	}
	cfg := fs.WindowsConfiguration
	if cfg != nil && cfg.AuditLogConfiguration != nil &&
		cfg.AuditLogConfiguration.AuditLogDestination != nil &&
		*cfg.AuditLogConfiguration.AuditLogDestination != "" {
		base.Status = fix.FixSkipped
		base.Message = "audit log already configured"
		return base
	}

	// Derive resource ID parts for log group name
	name := fsID
	if fs.ResourceARN != nil {
		// Extract file system ID from ARN if possible
		parts := strings.SplitN(*fs.ResourceARN, "/", 2)
		if len(parts) == 2 {
			name = parts[1]
		}
	}

	// Parse region and account from ARN
	region, account := "", ""
	if fs.ResourceARN != nil {
		arnParts := strings.Split(*fs.ResourceARN, ":")
		if len(arnParts) >= 6 {
			region = arnParts[3]
			account = arnParts[4]
		}
	}

	logGroupName := "/aws/fsx/windows/" + name
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s:*", region, account, logGroupName)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			fmt.Sprintf("would create log group %s", logGroupName),
			fmt.Sprintf("would enable SUCCESS_AND_FAILURE audit logging on FSx Windows file system %s", fsID),
		}
		return base
	}

	// Create log group (ignore AlreadyExistsException)
	_, cgErr := f.clients.CloudWatchLogs.CreateLogGroup(fctx.Ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroupName),
	})
	if cgErr != nil && !strings.Contains(cgErr.Error(), "ResourceAlreadyExistsException") {
		base.Status = fix.FixFailed
		base.Message = "create log group: " + cgErr.Error()
		return base
	}

	_, err = f.clients.FSx.UpdateFileSystem(fctx.Ctx, &fsx.UpdateFileSystemInput{
		FileSystemId: aws.String(fsID),
		WindowsConfiguration: &fsxtypes.UpdateFileSystemWindowsConfiguration{
			AuditLogConfiguration: &fsxtypes.WindowsAuditLogCreateConfiguration{
				FileAccessAuditLogLevel:       fsxtypes.WindowsAccessAuditLogLevelSuccessAndFailure,
				FileShareAccessAuditLogLevel:  fsxtypes.WindowsAccessAuditLogLevelSuccessAndFailure,
				AuditLogDestination:           aws.String(logGroupArn),
			},
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update file system: " + err.Error()
		return base
	}
	base.Steps = []string{
		fmt.Sprintf("created log group %s", logGroupName),
		fmt.Sprintf("enabled SUCCESS_AND_FAILURE audit logging on FSx Windows file system %s", fsID),
	}
	base.Status = fix.FixApplied
	return base
}
